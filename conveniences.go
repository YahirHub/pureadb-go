package adb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
)

func LoadOrCreateKey(path, name string) (*Key, error) {
	if data, err := os.ReadFile(path); err == nil {
		return ParsePrivateKeyPEM(data, name)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	k, err := GenerateKey(name)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, k.MarshalPrivateKeyPEM(), 0600); err != nil {
		return nil, err
	}
	return k, nil
}

func (c *Client) Exec(ctx context.Context, command string) ([]byte, error) {
	s, err := c.Conn.Open(ctx, "exec:"+command)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	var out bytes.Buffer
	done := make(chan error, 1)
	go func() { _, e := io.Copy(&out, s); done <- e }()
	select {
	case <-ctx.Done():
		_ = s.Close()
		return out.Bytes(), ctx.Err()
	case err := <-done:
		return out.Bytes(), err
	}
}

func (c *Client) Install(ctx context.Context, apkPath string) error {
	return c.InstallAPK(ctx, apkPath, InstallOptions{Replace: true})
}

func (c *Client) Uninstall(ctx context.Context, packageName string, keepData bool) error {
	cmd := "pm uninstall "
	if keepData {
		cmd += "-k "
	}
	cmd += shellQuote(packageName)
	out, err := c.Shell(ctx, cmd)
	if err != nil {
		return err
	}
	if !strings.Contains(out, "Success") {
		return fmt.Errorf("adb: uninstall failed: %s", strings.TrimSpace(out))
	}
	return nil
}

func (c *Client) Packages(ctx context.Context) ([]string, error) {
	out, err := c.Shell(ctx, "pm list packages")
	if err != nil {
		return nil, err
	}
	var pkgs []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package:") {
			pkgs = append(pkgs, strings.TrimPrefix(line, "package:"))
		}
	}
	return pkgs, nil
}

// Forward represents a host-side TCP forward backed directly by ADB streams.
type Forward struct {
	ln     net.Listener
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// ForwardTCP listens on localAddress (for example "127.0.0.1:8080") and forwards
// each accepted socket to tcp:remotePort on Android without an adb server.
func (c *Client) ForwardTCP(ctx context.Context, localAddress string, remotePort int) (*Forward, error) {
	if remotePort <= 0 || remotePort > 65535 {
		return nil, errors.New("adb: invalid remote TCP port")
	}
	ln, err := net.Listen("tcp", localAddress)
	if err != nil {
		return nil, err
	}
	fctx, cancel := context.WithCancel(ctx)
	f := &Forward{ln: ln, cancel: cancel}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		go func() { <-fctx.Done(); _ = ln.Close() }()
		for {
			hostConn, err := ln.Accept()
			if err != nil {
				return
			}
			f.wg.Add(1)
			go func(h net.Conn) {
				defer f.wg.Done()
				defer h.Close()
				s, err := c.Conn.Open(fctx, fmt.Sprintf("tcp:%d", remotePort))
				if err != nil {
					return
				}
				defer s.Close()
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(s, h); _ = s.Close(); done <- struct{}{} }()
				go func() { _, _ = io.Copy(h, s); done <- struct{}{} }()
				<-done
			}(hostConn)
		}
	}()
	return f, nil
}

func (f *Forward) Addr() net.Addr {
	if f == nil || f.ln == nil {
		return nil
	}
	return f.ln.Addr()
}
func (f *Forward) Close() error {
	if f == nil {
		return nil
	}
	f.cancel()
	err := f.ln.Close()
	f.wg.Wait()
	return err
}
