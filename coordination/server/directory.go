package server

import (
	"container/list"
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/Silo-Server/shunpike/coordination/protocol"
)

const directoryReadTimeout = 2 * time.Second

// DirectoryOptions sets the cache bound, negative-cache lifetime and refresh
// period. Zero selects 4096 entries, 2 s misses and 10 s refresh; nil Clock uses
// time.Now. Nonpositive explicit limits use those defaults as well.
type DirectoryOptions struct {
	MaxEntries int
	MissTTL    time.Duration
	Refresh    time.Duration
	Clock      func() time.Time
}

// PeerEntry is a live device or host view. Device Policy is opaque; hosts have
// nil Policy and a zero Ref. Expires is the earliest lease/presence deadline.
type PeerEntry struct {
	NodeKey   protocol.NodeKey
	Ref       DeviceRef
	IsHost    bool
	DiscoKey  protocol.DiscoKey
	Endpoints []netip.AddrPort
	Policy    []byte
	Expires   time.Time
}

type cacheEntry struct {
	key       protocol.NodeKey
	peer      *PeerEntry
	missUntil time.Time
}
type directoryRead struct {
	key  protocol.NodeKey
	done chan struct{}
}

// Directory keeps a bounded LRU and coalesces asynchronous misses per node key.
// Call Run to refresh held entries; Lookup and Devices also reject local expiry.
// Changed has one reader and coalesces unread notifications.
type Directory struct {
	st      Store
	o       DirectoryOptions
	mu      sync.Mutex
	lru     list.List
	entries map[protocol.NodeKey]*list.Element
	pending map[protocol.NodeKey]*directoryRead
	changed chan struct{}
}

// NewDirectory constructs an empty cache. Lookup performs no synchronous store
// I/O.
func NewDirectory(st Store, o DirectoryOptions) *Directory {
	if o.MaxEntries <= 0 {
		o.MaxEntries = 4096
	}
	if o.MissTTL <= 0 {
		o.MissTTL = 2 * time.Second
	}
	if o.Refresh <= 0 {
		o.Refresh = 10 * time.Second
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	return &Directory{st: st, o: o, entries: make(map[protocol.NodeKey]*list.Element), pending: make(map[protocol.NodeKey]*directoryRead), changed: make(chan struct{}, 1)}
}
func clonePeer(p PeerEntry) PeerEntry {
	p.Endpoints = slices.Clone(p.Endpoints)
	p.Policy = slices.Clone(p.Policy)
	return p
}
func devicePeer(d Device, now time.Time) (PeerEntry, bool) {
	if d.Registration == nil || !now.Before(d.LeaseExpires) || !now.Before(d.PresenceExpires) {
		return PeerEntry{}, false
	}
	expiry := d.LeaseExpires
	if d.PresenceExpires.Before(expiry) {
		expiry = d.PresenceExpires
	}
	return PeerEntry{NodeKey: d.NodeKey, Ref: d.Ref, DiscoKey: d.Registration.DiscoKey, Endpoints: slices.Clone(d.Registration.Endpoints), Policy: slices.Clone(d.Policy), Expires: expiry}, true
}
func hostPeer(h HostEntry) PeerEntry {
	return PeerEntry{NodeKey: h.NodeKey, IsHost: true, DiscoKey: h.DiscoKey, Endpoints: slices.Clone(h.Endpoints), Expires: h.PresenceExpires}
}
func (d *Directory) notify() {
	select {
	case d.changed <- struct{}{}:
	default:
	}
}
func (d *Directory) remove(e *list.Element) {
	c := e.Value.(*cacheEntry)
	delete(d.entries, c.key)
	d.lru.Remove(e)
	if c.peer != nil {
		d.notify()
	}
}
func (d *Directory) prune(now time.Time) {
	for _, e := range d.entries {
		c := e.Value.(*cacheEntry)
		if c.peer != nil && !now.Before(c.peer.Expires) || c.peer == nil && !now.Before(c.missUntil) {
			d.remove(e)
		}
	}
}
func peerEqual(a, b PeerEntry) bool {
	return a.NodeKey == b.NodeKey && a.Ref == b.Ref && a.IsHost == b.IsHost && a.DiscoKey == b.DiscoKey && slices.Equal(a.Endpoints, b.Endpoints) && slices.Equal(a.Policy, b.Policy) && a.Expires.Equal(b.Expires)
}
func (d *Directory) put(k protocol.NodeKey, p *PeerEntry, now time.Time) {
	c := &cacheEntry{key: k, missUntil: now.Add(d.o.MissTTL)}
	if p != nil {
		copy := clonePeer(*p)
		c.peer = &copy
	}
	if e := d.entries[k]; e != nil {
		old := e.Value.(*cacheEntry)
		if old.peer != nil && c.peer != nil && peerEqual(*old.peer, *c.peer) {
			return
		}
		e.Value = c
		if old.peer != nil || c.peer != nil {
			d.notify()
		}
		return
	}
	d.entries[k] = d.lru.PushFront(c)
	if c.peer != nil {
		d.notify()
	}
	for d.lru.Len() > d.o.MaxEntries {
		d.remove(d.lru.Back())
	}
}

// Lookup returns a caller-owned cache hit. A miss returns false immediately and
// starts at most one store read for k. Absent keys stay negative for MissTTL;
// unavailable storage never creates a positive or negative cache entry.
// A shared read retains the caller's context values but has its own 2-second
// timeout; canceling one caller does not cancel the read for other waiters.
func (d *Directory) Lookup(ctx context.Context, k protocol.NodeKey) (PeerEntry, bool) {
	d.mu.Lock()
	now := d.o.Clock()
	if e := d.entries[k]; e != nil {
		c := e.Value.(*cacheEntry)
		if c.peer != nil && !now.Before(c.peer.Expires) || c.peer == nil && !now.Before(c.missUntil) {
			d.remove(e)
		}
	}
	if e := d.entries[k]; e != nil {
		d.lru.MoveToFront(e)
		c := e.Value.(*cacheEntry)
		if c.peer != nil {
			p := clonePeer(*c.peer)
			d.mu.Unlock()
			return p, true
		}
		d.mu.Unlock()
		return PeerEntry{}, false
	}
	if d.pending[k] == nil && ctx.Err() == nil {
		r := &directoryRead{key: k}
		d.pending[k] = r
		readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), directoryReadTimeout)
		go func() {
			defer cancel()
			d.load(readCtx, r)
		}()
	}
	d.mu.Unlock()
	return PeerEntry{}, false
}
func (d *Directory) read(ctx context.Context, k protocol.NodeKey, now time.Time) (PeerEntry, bool, error) {
	device, err := d.st.DeviceByNodeKey(ctx, k, now)
	if err == nil {
		p, ok := devicePeer(device, now)
		return p, ok, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return PeerEntry{}, false, err
	}
	hosts, err := d.st.Hosts(ctx, now)
	if err != nil {
		return PeerEntry{}, false, err
	}
	for _, h := range hosts {
		if h.NodeKey == k && now.Before(h.PresenceExpires) {
			return hostPeer(h), true, nil
		}
	}
	return PeerEntry{}, false, nil
}
func (d *Directory) load(ctx context.Context, r *directoryRead) {
	p, ok, err := d.read(ctx, r.key, d.o.Clock())
	d.mu.Lock()
	defer d.mu.Unlock()
	defer func() {
		if r.done != nil {
			close(r.done)
		}
	}()
	if d.pending[r.key] != r {
		return
	}
	delete(d.pending, r.key)
	if err != nil {
		return
	}
	now := d.o.Clock()
	if ok && now.Before(p.Expires) {
		d.put(r.key, &p, now)
	} else {
		d.put(r.key, nil, now)
	}
}

// Invalidate removes a cached key and rejects completion of its old in-flight
// read. The next Lookup starts a new read. Removing a peer fires Changed.
func (d *Directory) Invalidate(k protocol.NodeKey) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.pending, k)
	if e := d.entries[k]; e != nil {
		d.remove(e)
	}
}

// Reload reads k from the store and replaces its cached entry in place. The old
// entry stays visible until the read lands, and Changed fires only when the new
// entry differs. A failed read keeps the old entry. The call rejects completion
// of any earlier in-flight read for k. Use Invalidate to drop a key.
func (d *Directory) Reload(ctx context.Context, k protocol.NodeKey) {
	r := &directoryRead{key: k}
	d.mu.Lock()
	d.pending[k] = r
	d.mu.Unlock()
	readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), directoryReadTimeout)
	defer cancel()
	d.load(readCtx, r)
}

// Devices returns copies of held live device entries, sorted by node key.
// Expired entries are removed and fire Changed, including during a store outage.
func (d *Directory) Devices() []PeerEntry {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.prune(d.o.Clock())
	result := make([]PeerEntry, 0, len(d.entries))
	for _, e := range d.entries {
		c := e.Value.(*cacheEntry)
		if c.peer != nil && !c.peer.IsHost {
			result = append(result, clonePeer(*c.peer))
		}
	}
	slices.SortFunc(result, func(a, b PeerEntry) int { return slices.Compare(a.NodeKey[:], b.NodeKey[:]) })
	return result
}

// Changed returns the capacity-1 channel for add, removal, disco key, endpoint,
// policy and expiry changes. Notifications never block and unread events coalesce.
func (d *Directory) Changed() <-chan struct{} { return d.changed }

type accountBatch struct {
	devices map[protocol.NodeKey]Device
	err     error
}

func (d *Directory) refresh(ctx context.Context) {
	d.mu.Lock()
	held := make(map[protocol.NodeKey]*cacheEntry, len(d.entries))
	accounts := make(map[AccountID]accountBatch)
	needHosts := false
	for k, e := range d.entries {
		c := e.Value.(*cacheEntry)
		held[k] = c
		if c.peer != nil && !c.peer.IsHost {
			accounts[c.peer.Ref.Account] = accountBatch{}
		} else {
			needHosts = true
		}
	}
	d.mu.Unlock()
	now := d.o.Clock()
	// One account read refreshes all held devices belonging to that account.
	for account := range accounts {
		ds, err := d.st.ListDevices(ctx, account, now)
		batch := accountBatch{devices: make(map[protocol.NodeKey]Device, len(ds)), err: err}
		for _, device := range ds {
			batch.devices[device.NodeKey] = device
		}
		accounts[account] = batch
	}
	var hosts []HostEntry
	var hostsErr error
	if needHosts {
		hosts, hostsErr = d.st.Hosts(ctx, now)
	}
	byHost := make(map[protocol.NodeKey]HostEntry, len(hosts))
	for _, h := range hosts {
		byHost[h.NodeKey] = h
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now = d.o.Clock()
	for k, old := range held {
		e := d.entries[k]
		if e == nil || e.Value.(*cacheEntry) != old {
			continue
		}
		var p PeerEntry
		var ok bool
		var err error
		if old.peer != nil && !old.peer.IsHost {
			batch := accounts[old.peer.Ref.Account]
			err = batch.err
			if device, found := batch.devices[k]; found && device.Ref == old.peer.Ref {
				p, ok = devicePeer(device, now)
			}
		} else {
			err = hostsErr
			if h, found := byHost[k]; found && now.Before(h.PresenceExpires) {
				p, ok = hostPeer(h), true
			}
		}
		if err != nil {
			continue
		}
		if ok {
			d.put(k, &p, now)
		} else if old.peer != nil {
			d.remove(e)
		}
	}
	d.prune(now)
}

// Run refreshes held devices in one batch per account and held hosts in one
// scan every Refresh. Failed reads retain entries only until their own expiry.
// Cancellation returns nil; it does not clear the cache or close Changed.
func (d *Directory) Run(ctx context.Context) error {
	ticker := time.NewTicker(d.o.Refresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			d.refresh(ctx)
		}
	}
}
