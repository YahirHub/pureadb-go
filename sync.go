package adb

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"
)

const syncChunkSize = 64 * 1024

func (c *Client) PushReader(ctx context.Context, r io.Reader, remotePath string, mode uint32, mtime time.Time) error {
	s, err := c.Conn.Open(ctx, "sync:")
	if err != nil {
		return err
	}
	defer s.Close()

	name := fmt.Sprintf("%s,%d", remotePath, mode)
	if err := syncWriteRequest(ctx, s, "SEND", []byte(name)); err != nil {
		return err
	}
	buf := make([]byte, syncChunkSize)
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			if err := syncWriteRequest(ctx, s, "DATA", buf[:n]); err != nil {
				return err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	var done [8]byte
	copy(done[:4], "DONE")
	binary.LittleEndian.PutUint32(done[4:], uint32(mtime.Unix()))
	if _, err := s.WriteContext(ctx, done[:]); err != nil {
		return err
	}

	id, payloadOrValue, err := syncReadResponse(s)
	if err != nil {
		return err
	}
	switch id {
	case "OKAY":
		return nil
	case "FAIL":
		return fmt.Errorf("adb sync: %s", string(payloadOrValue))
	default:
		return fmt.Errorf("%w: unexpected sync SEND response %q", ErrProtocol, id)
	}
}

func (c *Client) PullWriter(ctx context.Context, remotePath string, w io.Writer) error {
	s, err := c.Conn.Open(ctx, "sync:")
	if err != nil {
		return err
	}
	defer s.Close()
	if err := syncWriteRequest(ctx, s, "RECV", []byte(remotePath)); err != nil {
		return err
	}
	br := bufio.NewReader(s)
	for {
		var hdr [8]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return err
		}
		id := string(hdr[:4])
		n := binary.LittleEndian.Uint32(hdr[4:])
		switch id {
		case "DATA":
			if n > syncChunkSize {
				return fmt.Errorf("%w: sync DATA chunk too large: %d", ErrProtocol, n)
			}
			if _, err := io.CopyN(w, br, int64(n)); err != nil {
				return err
			}
		case "DONE":
			return nil
		case "FAIL":
			msg := make([]byte, int(n))
			if _, err := io.ReadFull(br, msg); err != nil {
				return err
			}
			return fmt.Errorf("adb sync: %s", strings.TrimSpace(string(msg)))
		default:
			return fmt.Errorf("%w: unexpected sync RECV response %q", ErrProtocol, id)
		}
	}
}

func syncWriteRequest(ctx context.Context, s *Stream, id string, payload []byte) error {
	if len(id) != 4 {
		return fmt.Errorf("adb sync: invalid id %q", id)
	}
	var hdr [8]byte
	copy(hdr[:4], id)
	binary.LittleEndian.PutUint32(hdr[4:], uint32(len(payload)))
	if _, err := s.WriteContext(ctx, hdr[:]); err != nil {
		return err
	}
	if len(payload) != 0 {
		_, err := s.WriteContext(ctx, payload)
		return err
	}
	return nil
}

// syncReadResponse returns either a four-byte little-endian value encoded as a
// 4-byte slice (OKAY/DONE) or the FAIL payload. It is intended for SEND replies.
func syncReadResponse(r io.Reader) (string, []byte, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", nil, err
	}
	id := string(hdr[:4])
	n := binary.LittleEndian.Uint32(hdr[4:])
	if id == "FAIL" {
		msg := make([]byte, int(n))
		if _, err := io.ReadFull(r, msg); err != nil {
			return "", nil, err
		}
		return id, msg, nil
	}
	return id, hdr[4:8], nil
}
