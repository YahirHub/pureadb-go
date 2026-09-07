package adb

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Client struct {
	Conn *Connection
}

func Connect(ctx context.Context, address string, key *Key) (*Client, error) {
	conn, err := Dial(ctx, address, key)
	if err != nil {
		return nil, err
	}
	return &Client{Conn: conn}, nil
}

func (c *Client) Close() error { return c.Conn.Close() }

func (c *Client) Shell(ctx context.Context, command string) (string, error) {
	s, err := c.Conn.Open(ctx, "shell:"+command)
	if err != nil {
		return "", err
	}
	defer s.Close()
	var out bytes.Buffer
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(&out, s)
		done <- err
	}()
	select {
	case <-ctx.Done():
		_ = s.Close()
		return out.String(), ctx.Err()
	case err := <-done:
		if err != nil {
			return out.String(), err
		}
		return out.String(), nil
	}
}

func (c *Client) ShellStream(ctx context.Context, command string) (*Stream, error) {
	return c.Conn.Open(ctx, "shell:"+command)
}

func (c *Client) Push(ctx context.Context, localPath, remotePath string, mode uint32) error {
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if mode == 0 {
		mode = 0644
	}
	return c.PushReader(ctx, f, remotePath, mode, st.ModTime())
}

func (c *Client) Pull(ctx context.Context, remotePath, localPath string) error {
	if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil && filepath.Dir(localPath) != "." {
		return err
	}
	f, err := os.Create(localPath)
	if err != nil {
		return err
	}
	err = c.PullWriter(ctx, remotePath, f)
	closeErr := f.Close()
	if err != nil {
		_ = os.Remove(localPath)
		return err
	}
	return closeErr
}

type InstallOptions struct {
	Replace                 bool
	GrantRuntimePermissions bool
	AllowTest               bool
	Downgrade               bool
	ExtraArgs               []string
}

func (c *Client) InstallAPK(ctx context.Context, apkPath string, opts InstallOptions) error {
	name := filepath.Base(apkPath)
	remote := "/data/local/tmp/pureadb-" + sanitizeFilename(name)
	if err := c.Push(ctx, apkPath, remote, 0644); err != nil {
		return err
	}
	defer func() { _, _ = c.Shell(context.Background(), "rm -f "+shellQuote(remote)) }()

	args := []string{"pm", "install"}
	if opts.Replace {
		args = append(args, "-r")
	}
	if opts.GrantRuntimePermissions {
		args = append(args, "-g")
	}
	if opts.AllowTest {
		args = append(args, "-t")
	}
	if opts.Downgrade {
		args = append(args, "-d")
	}
	args = append(args, opts.ExtraArgs...)
	args = append(args, remote)
	for i := range args {
		args[i] = shellQuote(args[i])
	}
	out, err := c.Shell(ctx, strings.Join(args, " "))
	if err != nil {
		return err
	}
	if !strings.Contains(out, "Success") {
		return fmt.Errorf("%w: %s", ErrInstallFailed, strings.TrimSpace(out))
	}
	return nil
}

func sanitizeFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
