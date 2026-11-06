package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// DecodeRegistration reads one registration object, capped at 64 KiB.
// It refuses unknown fields and trailing data, then validates the fields.
// Failures wrap ErrTooLarge, ErrInvalid or an underlying reader error.
func DecodeRegistration(r io.Reader) (Registration, error) {
	var value Registration
	if err := decodeObject(r, 64<<10, &value); err != nil {
		return Registration{}, err
	}
	if err := value.Validate(); err != nil {
		return Registration{}, err
	}
	return value, nil
}

// DecodeNetmap reads one netmap object, capped at 1 MiB, then validates it.
// It refuses unknown fields and trailing data. Failures wrap ErrTooLarge,
// ErrInvalid or an underlying reader error.
func DecodeNetmap(r io.Reader) (Netmap, error) {
	var value Netmap
	if err := decodeObject(r, 1<<20, &value); err != nil {
		return Netmap{}, err
	}
	if err := value.Validate(); err != nil {
		return Netmap{}, err
	}
	return value, nil
}

func decodeObject(r io.Reader, limit int64, value any) error {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return fmt.Errorf("read coordination document: %w", err)
	}
	if int64(len(data)) > limit {
		return fmt.Errorf("%w: limit is %d bytes", ErrTooLarge, limit)
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return fmt.Errorf("%w: expected one JSON object", ErrInvalid)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("%w: decode object: %w", ErrInvalid, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	return nil
}
