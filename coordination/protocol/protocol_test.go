package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"testing"
)

type documentVector struct {
	// Name identifies the case.
	Name string `json:"name"`
	// Body contains the input JSON object.
	Body json.RawMessage `json:"body"`
	// Want is accept, invalid or too_large.
	Want string `json:"want"`
	// Suffix appends bytes after the object.
	Suffix string `json:"suffix"`
	// Size pads the input to an exact byte count when nonzero.
	Size int `json:"size"`
	// DecodeOnly excludes a wire-only case from Go-value validation.
	DecodeOnly bool `json:"decode_only"`
}

func readVectors[T any](t *testing.T, name string) []T {
	t.Helper()
	data, err := os.ReadFile("../vectors/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []T
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("empty vector set")
	}
	return vectors
}

func testDocuments[T any](t *testing.T, name string, decode func(io.Reader) (T, error), validate func(T) error) {
	t.Helper()
	for _, v := range readVectors[documentVector](t, name) {
		t.Run(v.Name, func(t *testing.T) {
			body := append(bytes.Clone(v.Body), v.Suffix...)
			if v.Size != 0 {
				if len(body) > v.Size {
					t.Fatalf("fixture body has %d bytes, exceeds target %d", len(body), v.Size)
				}
				body = append(body, bytes.Repeat([]byte{' '}, v.Size-len(body))...)
			}
			got, err := decode(bytes.NewReader(body))
			assertVectorError(t, v.Want, err)
			if v.Want == "accept" {
				var want T
				if err := json.Unmarshal(v.Body, &want); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("decoded document = %#v, want %#v", got, want)
				}
			}
			if !v.DecodeOnly {
				var value T
				if err := json.Unmarshal(v.Body, &value); err != nil {
					t.Fatal(err)
				}
				assertVectorError(t, v.Want, validate(value))
			}
		})
	}
}

func assertVectorError(t *testing.T, want string, err error) {
	t.Helper()
	switch want {
	case "accept":
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case "invalid":
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("error = %v, want ErrInvalid", err)
		}
	case "too_large":
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("error = %v, want ErrTooLarge", err)
		}
	default:
		t.Fatalf("unrecognized vector outcome %q", want)
	}
}

// TestRegistrationVectors checks every registration limit and identity rule.
func TestRegistrationVectors(t *testing.T) {
	testDocuments(t, "registration", DecodeRegistration, Registration.Validate)
}

// TestNetmapVectors checks host identities, regions, timing and decode limits.
func TestNetmapVectors(t *testing.T) {
	testDocuments(t, "netmap", DecodeNetmap, Netmap.Validate)
}

func TestConfirmationValidate(t *testing.T) {
	valid := Confirmation{Peer: NodeKey{1}, DiscoKey: DiscoKey{2}, Endpoint: netip.MustParseAddrPort("192.0.2.1:443")}
	for _, tc := range []struct {
		name string
		c    Confirmation
		want string
	}{
		{"valid", valid, "accept"},
		{"zero-endpoint", Confirmation{Peer: valid.Peer, DiscoKey: valid.DiscoKey}, "invalid"},
		{"zero-disco-key", Confirmation{Peer: valid.Peer, Endpoint: valid.Endpoint}, "invalid"},
		{"zero-peer", Confirmation{DiscoKey: valid.DiscoKey, Endpoint: valid.Endpoint}, "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertVectorError(t, tc.want, tc.c.Validate())
		})
	}
}

// TestKeyTextRoundTrip checks canonical key text and atomic rejection of bad text.
func TestKeyTextRoundTrip(t *testing.T) {
	for _, prefix := range []string{"nodekey:", "discokey:"} {
		t.Run(prefix, func(t *testing.T) {
			newKey := func() interface {
				MarshalText() ([]byte, error)
				UnmarshalText([]byte) error
				String() string
				IsZero() bool
			} {
				if prefix == "nodekey:" {
					return new(NodeKey)
				}
				return new(DiscoKey)
			}
			key := newKey()
			if !key.IsZero() {
				t.Fatal("new key is not zero")
			}
			text := prefix + strings.Repeat("ab", 32)
			if err := key.UnmarshalText([]byte(text)); err != nil {
				t.Fatal(err)
			}
			encoded, err := key.MarshalText()
			if err != nil || string(encoded) != text || key.String() != text || key.IsZero() {
				t.Fatalf("key text = %q, string = %q, zero = %v, error = %v", encoded, key.String(), key.IsZero(), err)
			}
			other := "nodekey:"
			if prefix == other {
				other = "discokey:"
			}
			for name, bad := range map[string]string{
				"wrong-prefix": other + strings.Repeat("ab", 32),
				"short":        prefix + "ab",
				"uppercase":    prefix + strings.Repeat("AB", 32),
				"invalid-hex":  prefix + strings.Repeat("zz", 32),
			} {
				t.Run(name, func(t *testing.T) {
					if err := key.UnmarshalText([]byte(bad)); !errors.Is(err, ErrInvalid) {
						t.Fatalf("error = %v, want ErrInvalid", err)
					}
					if key.String() != text {
						t.Fatalf("failed decode changes key to %q", key.String())
					}
				})
			}
		})
	}
}

func referenceNetmap(t *testing.T) Netmap {
	t.Helper()
	var m Netmap
	vectors := readVectors[documentVector](t, "netmap")
	if err := json.Unmarshal(vectors[0].Body, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestNetmapVersionDeterministic checks ordering, field coverage and input ownership.
func TestNetmapVersionDeterministic(t *testing.T) {
	m := referenceNetmap(t)
	m.Regions = append(m.Regions, Region{ID: 2, Code: "second", URL: "https://other.example/signal"})
	m.Hosts[0].Endpoints = append(m.Hosts[0].Endpoints, netip.MustParseAddrPort("[2001:db8::2]:443"))
	m.Hosts[0].Confirmation = &Confirmation{Peer: NodeKey{1}, DiscoKey: DiscoKey{1}, Endpoint: netip.MustParseAddrPort("192.0.2.1:443")}
	second := m.Hosts[0]
	second.Label, second.NodeKey = "node:two", NodeKey{3}
	m.Hosts = append(m.Hosts, second)
	want := NetmapVersion(m)
	if decoded, err := base64.RawURLEncoding.DecodeString(want); err != nil || len(decoded) != sha256.Size {
		t.Fatalf("version = %q, want base64url SHA-256", want)
	}
	t.Run("order", func(t *testing.T) {
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		var reordered Netmap
		if err := json.Unmarshal(data, &reordered); err != nil {
			t.Fatal(err)
		}
		slices.Reverse(reordered.Hosts)
		slices.Reverse(reordered.Regions)
		for i := range reordered.Hosts {
			slices.Reverse(reordered.Hosts[i].Endpoints)
		}
		if got := NetmapVersion(reordered); got != want {
			t.Fatalf("reordered version = %q, want %q", got, want)
		}
	})
	t.Run("nil-empty", func(t *testing.T) {
		for _, field := range []string{"hosts", "endpoints"} {
			t.Run(field, func(t *testing.T) {
				nilMap, emptyMap := referenceNetmap(t), referenceNetmap(t)
				if field == "hosts" {
					nilMap.Hosts, emptyMap.Hosts = nil, []Host{}
				} else {
					nilMap.Hosts[0].Endpoints, emptyMap.Hosts[0].Endpoints = nil, []netip.AddrPort{}
				}
				before, err := json.Marshal([]Netmap{nilMap, emptyMap})
				if err != nil {
					t.Fatal(err)
				}
				if got, want := NetmapVersion(nilMap), NetmapVersion(emptyMap); got != want {
					t.Errorf("nil %s version = %q, want empty version %q", field, got, want)
				}
				after, err := json.Marshal([]Netmap{nilMap, emptyMap})
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(before, after) {
					t.Fatal("version calculation mutates caller's netmap")
				}
			})
		}
	})
	t.Run("version-excluded", func(t *testing.T) {
		changed := m
		changed.Version = "ignored"
		if got := NetmapVersion(changed); got != want {
			t.Fatalf("version field changes hash to %q, want %q", got, want)
		}
	})
	changes := map[string]func(*Netmap){
		"lease":                 func(m *Netmap) { m.LeaseSeconds++ },
		"refresh":               func(m *Netmap) { m.RefreshSeconds-- },
		"region-id":             func(m *Netmap) { m.Regions[0].ID++ },
		"region-code":           func(m *Netmap) { m.Regions[0].Code += "x" },
		"region-url":            func(m *Netmap) { m.Regions[0].URL += "/x" },
		"label":                 func(m *Netmap) { m.Hosts[0].Label += "x" },
		"node-key":              func(m *Netmap) { m.Hosts[0].NodeKey[0]++ },
		"disco-key":             func(m *Netmap) { m.Hosts[0].DiscoKey[0]++ },
		"endpoint":              func(m *Netmap) { m.Hosts[0].Endpoints[0] = netip.MustParseAddrPort("192.0.2.9:443") },
		"home-region":           func(m *Netmap) { m.Hosts[0].HomeRegion++ },
		"origin":                func(m *Netmap) { m.Hosts[0].Origin = "opaque" },
		"confirmation-peer":     func(m *Netmap) { m.Hosts[0].Confirmation.Peer[0]++ },
		"confirmation-disco":    func(m *Netmap) { m.Hosts[0].Confirmation.DiscoKey[0]++ },
		"confirmation-endpoint": func(m *Netmap) { m.Hosts[0].Confirmation.Endpoint = netip.MustParseAddrPort("192.0.2.8:443") },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			var changed Netmap
			if err := json.Unmarshal(data, &changed); err != nil {
				t.Fatal(err)
			}
			change(&changed)
			if got := NetmapVersion(changed); got == want {
				t.Fatalf("field change leaves version %q unchanged", got)
			}
		})
	}
	before, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	_ = NetmapVersion(m)
	after, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("version calculation mutates caller's netmap")
	}
}

// TestProtocolImportsStandardLibraryOnly refuses any nonstandard transitive import.
func TestProtocolImportsStandardLibraryOnly(t *testing.T) {
	command := exec.Command("go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", ".")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, output)
	}
	if got := strings.Fields(string(output)); !slices.Equal(got, []string{"github.com/darthShadow/shunpike/coordination/protocol"}) {
		t.Fatalf("nonstandard packages = %v, want only protocol itself", got)
	}
}

// TestDecodeReaderFailure checks that decoding preserves input failure identity.
func TestDecodeReaderFailure(t *testing.T) {
	failure := errors.New("input failure")
	for name, decode := range map[string]func(io.Reader) error{
		"registration": func(r io.Reader) error { _, err := DecodeRegistration(r); return err },
		"netmap":       func(r io.Reader) error { _, err := DecodeNetmap(r); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if err := decode(failedReader{failure}); !errors.Is(err, failure) {
				t.Fatalf("error = %v, want original reader failure %v", err, failure)
			}
		})
	}
}

type failedReader struct{ err error }

func (r failedReader) Read([]byte) (int, error) { return 0, r.err }

// ExampleNodeKey shows the canonical public node-key encoding.
func ExampleNodeKey() {
	var key NodeKey
	key[31] = 1
	fmt.Println(key.String())
	// Output: nodekey:0000000000000000000000000000000000000000000000000000000000000001
}
