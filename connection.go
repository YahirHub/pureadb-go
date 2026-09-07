package adb

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type DialOptions struct {
	// LegacyAuth sends the RSA AUTH flow instead of requiring STLS.
	// Use it for old `adb tcpip 5555` endpoints, not Android 11+ Wireless Debugging.
	LegacyAuth bool
	// AllowPublicKeyAuth sends the public key after a failed signature attempt,
	// which can cause Android to show the classic USB/TCP authorization dialog.
	AllowPublicKeyAuth bool
}

type Connection struct {
	conn       net.Conn
	key        *Key
	maxPayload uint32
	banner     string

	writeMu sync.Mutex
	mu      sync.Mutex
	streams map[uint32]*Stream
	nextID  atomic.Uint32

	done      chan struct{}
	closeOnce sync.Once
	readErr   atomic.Value // errorBox
}

type errorBox struct{ err error }

func Dial(ctx context.Context, address string, key *Key) (*Connection, error) {
	return DialWithOptions(ctx, address, key, DialOptions{})
}

func DialWithOptions(ctx context.Context, address string, key *Key, opts DialOptions) (*Connection, error) {
	if key == nil || key.Private == nil {
		return nil, errors.New("adb: RSA key required")
	}
	d := net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	applyContextDeadline(ctx, raw)

	c := &Connection{
		conn: raw, key: key, maxPayload: adbMaxPayload,
		streams: make(map[uint32]*Stream), done: make(chan struct{}),
	}
	c.nextID.Store(0)

	if err := c.handshake(ctx, opts); err != nil {
		raw.Close()
		return nil, err
	}
	// A context deadline is only for dialing/handshake. Long-lived stream IO should
	// not inherit it after the connection is online.
	_ = c.conn.SetDeadline(noDeadline)
	go c.readLoop()
	return c, nil
}

var noDeadline time.Time

func (c *Connection) handshake(ctx context.Context, opts DialOptions) error {
	banner := []byte("host::features=cmd;")
	if len(banner) > adbMaxPayloadV1 {
		return errors.New("adb: host banner too large")
	}
	if err := writePacket(c.conn, packet{command: cmdCNXN, arg0: adbVersion, arg1: adbMaxPayload, data: banner}); err != nil {
		return err
	}

	sentSignature := false
	sentPublic := false
	for {
		p, err := readPacket(c.conn)
		if err != nil {
			return err
		}
		switch p.command {
		case cmdCNXN:
			c.maxPayload = p.arg1
			if c.maxPayload == 0 || c.maxPayload > adbMaxPayload {
				c.maxPayload = adbMaxPayload
			}
			c.banner = strings.TrimRight(string(p.data), "\x00")
			return nil

		case cmdSTLS:
			if opts.LegacyAuth {
				return fmt.Errorf("%w: endpoint requested TLS while LegacyAuth was selected", ErrProtocol)
			}
			if err := writePacket(c.conn, packet{command: cmdSTLS, arg0: adbTLSVersion}); err != nil {
				return err
			}
			cert, err := c.key.tlsCertificate()
			if err != nil {
				return err
			}
			tlsConn := tls.Client(c.conn, &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
				Certificates:       []tls.Certificate{cert},
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					// ADB supplies a custom CA-name hint based on authorized keys. With one
					// persistent key, always present our matching self-signed certificate.
					return &cert, nil
				},
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				return fmt.Errorf("adb: secure-connect TLS handshake: %w", err)
			}
			c.conn = tlsConn

		case cmdAUTH:
			if !opts.LegacyAuth {
				return fmt.Errorf("%w: endpoint requested legacy AUTH; pair Wireless Debugging first", ErrUnauthorized)
			}
			if p.arg0 != authToken {
				return fmt.Errorf("%w: unexpected AUTH type %d", ErrProtocol, p.arg0)
			}
			if !sentSignature {
				sig, err := c.key.SignADBToken(p.data)
				if err != nil {
					return err
				}
				if err := writePacket(c.conn, packet{command: cmdAUTH, arg0: authSignature, data: sig}); err != nil {
					return err
				}
				sentSignature = true
				continue
			}
			if opts.AllowPublicKeyAuth && !sentPublic {
				pub, err := c.key.PublicKeyADB()
				if err != nil {
					return err
				}
				payload := append([]byte(pub), 0)
				if err := writePacket(c.conn, packet{command: cmdAUTH, arg0: authPublicKey, data: payload}); err != nil {
					return err
				}
				sentPublic = true
				continue
			}
			return ErrUnauthorized

		default:
			return fmt.Errorf("%w: unexpected handshake packet %q", ErrProtocol, commandString(p.command))
		}
	}
}

func (c *Connection) Banner() string     { return c.banner }
func (c *Connection) MaxPayload() uint32 { return c.maxPayload }

func (c *Connection) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.done)
		err = c.conn.Close()
		c.mu.Lock()
		for _, s := range c.streams {
			s.finish(ErrClosed)
		}
		c.streams = make(map[uint32]*Stream)
		c.mu.Unlock()
	})
	return err
}

func (c *Connection) readLoop() {
	for {
		p, err := readPacket(c.conn)
		if err != nil {
			c.readErr.Store(errorBox{err: err})
			_ = c.Close()
			return
		}
		switch p.command {
		case cmdOKAY:
			c.mu.Lock()
			s := c.streams[p.arg1]
			c.mu.Unlock()
			if s != nil {
				s.handleOkay(p.arg0)
			}
		case cmdWRTE:
			c.mu.Lock()
			s := c.streams[p.arg1]
			c.mu.Unlock()
			if s != nil {
				if !s.deliver(p.data) {
					continue
				}
				_ = c.send(packet{command: cmdOKAY, arg0: p.arg1, arg1: p.arg0})
			}
		case cmdCLSE:
			c.mu.Lock()
			s := c.streams[p.arg1]
			delete(c.streams, p.arg1)
			c.mu.Unlock()
			if s != nil {
				s.finish(io.EOF)
			}
		}
	}
}

func (c *Connection) send(p packet) error {
	select {
	case <-c.done:
		return ErrClosed
	default:
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return writePacket(c.conn, p)
}

func (c *Connection) Open(ctx context.Context, service string) (*Stream, error) {
	id := c.nextID.Add(1)
	if id == 0 {
		id = c.nextID.Add(1)
	}
	s := newStream(c, id)
	c.mu.Lock()
	c.streams[id] = s
	c.mu.Unlock()
	payload := append([]byte(service), 0)
	if err := c.send(packet{command: cmdOPEN, arg0: id, data: payload}); err != nil {
		c.removeStream(id)
		return nil, err
	}
	select {
	case <-ctx.Done():
		_ = s.Close()
		return nil, ctx.Err()
	case <-s.opened:
		if err := s.err(); err != nil {
			return nil, err
		}
		return s, nil
	case <-c.done:
		return nil, c.connectionError()
	}
}

func (c *Connection) removeStream(id uint32) {
	c.mu.Lock()
	delete(c.streams, id)
	c.mu.Unlock()
}

func (c *Connection) connectionError() error {
	if v := c.readErr.Load(); v != nil {
		if b, ok := v.(errorBox); ok && b.err != nil {
			return b.err
		}
	}
	return ErrClosed
}
