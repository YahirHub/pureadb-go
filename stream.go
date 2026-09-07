package adb

import (
	"context"
	"errors"
	"io"
	"sync"
)

type Stream struct {
	conn    *Connection
	localID uint32

	mu       sync.Mutex
	remoteID uint32
	opened   chan struct{}
	openOnce sync.Once
	ack      chan struct{}
	recv     chan []byte
	done     chan struct{}
	doneOnce sync.Once
	endErr   error
	readBuf  []byte
}

func newStream(c *Connection, localID uint32) *Stream {
	return &Stream{
		conn: c, localID: localID,
		opened: make(chan struct{}), ack: make(chan struct{}, 1), recv: make(chan []byte, 8), done: make(chan struct{}),
	}
}

func (s *Stream) handleOkay(remote uint32) {
	s.mu.Lock()
	if s.remoteID == 0 {
		s.remoteID = remote
		s.mu.Unlock()
		s.openOnce.Do(func() { close(s.opened) })
		return
	}
	s.mu.Unlock()
	select {
	case s.ack <- struct{}{}:
	default:
	}
}

func (s *Stream) deliver(data []byte) bool {
	copyData := append([]byte(nil), data...)
	select {
	case <-s.done:
		return false
	case s.recv <- copyData:
		return true
	}
}

func (s *Stream) finish(err error) {
	s.doneOnce.Do(func() {
		s.mu.Lock()
		s.endErr = err
		s.mu.Unlock()
		s.openOnce.Do(func() { close(s.opened) })
		close(s.done)
	})
}

func (s *Stream) err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.endErr
}

func (s *Stream) Read(p []byte) (int, error) {
	for len(s.readBuf) == 0 {
		select {
		case data := <-s.recv:
			s.readBuf = data
		case <-s.done:
			// Drain data already queued before reporting EOF.
			select {
			case data := <-s.recv:
				s.readBuf = data
			default:
				if err := s.err(); err != nil && !errors.Is(err, io.EOF) {
					return 0, err
				}
				return 0, io.EOF
			}
		}
	}
	n := copy(p, s.readBuf)
	s.readBuf = s.readBuf[n:]
	return n, nil
}

func (s *Stream) Write(p []byte) (int, error) {
	return s.WriteContext(context.Background(), p)
}

func (s *Stream) WriteContext(ctx context.Context, p []byte) (int, error) {
	s.mu.Lock()
	remote := s.remoteID
	s.mu.Unlock()
	if remote == 0 {
		return 0, errors.New("adb: stream is not open")
	}
	max := int(s.conn.maxPayload)
	if max <= 0 || max > adbMaxPayload {
		max = adbMaxPayload
	}
	written := 0
	for written < len(p) {
		n := len(p) - written
		if n > max {
			n = max
		}
		chunk := append([]byte(nil), p[written:written+n]...)
		if err := s.conn.send(packet{command: cmdWRTE, arg0: s.localID, arg1: remote, data: chunk}); err != nil {
			return written, err
		}
		select {
		case <-ctx.Done():
			return written, ctx.Err()
		case <-s.ack:
			written += n
		case <-s.done:
			if err := s.err(); err != nil {
				return written, err
			}
			return written, ErrServiceClosed
		case <-s.conn.done:
			return written, s.conn.connectionError()
		}
	}
	return written, nil
}

func (s *Stream) Close() error {
	s.mu.Lock()
	remote := s.remoteID
	s.mu.Unlock()
	if remote != 0 {
		_ = s.conn.send(packet{command: cmdCLSE, arg0: s.localID, arg1: remote})
	}
	s.conn.removeStream(s.localID)
	s.finish(io.EOF)
	return nil
}
