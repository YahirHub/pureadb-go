package adb

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestSPAKE2Agreement(t *testing.T) {
	password := []byte("1234560123456789abcdefghijklmnopqrstuvwxyz")
	a, err := newSpake2(spakeAlice, password)
	if err != nil {
		t.Fatal(err)
	}
	b, err := newSpake2(spakeBob, password)
	if err != nil {
		t.Fatal(err)
	}
	ka, err := a.Finish(b.Message())
	if err != nil {
		t.Fatal(err)
	}
	kb, err := b.Finish(a.Message())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ka, kb) {
		t.Fatal("SPAKE2 keys do not agree")
	}
	if len(ka) != 64 {
		t.Fatalf("got %d-byte SPAKE2 key", len(ka))
	}
}

func TestADBPublicKeyEncoding(t *testing.T) {
	k, err := GenerateKey("test@go")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := k.PublicKeyADB()
	if err != nil {
		t.Fatal(err)
	}
	sp := bytes.IndexByte([]byte(pub), ' ')
	if sp < 0 {
		t.Fatal("missing key comment")
	}
	blob, err := base64.StdEncoding.DecodeString(pub[:sp])
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) != adbRSAPublicKeySize {
		t.Fatalf("public blob size=%d", len(blob))
	}
	if readLE32(blob[:4]) != 64 {
		t.Fatalf("modulus words=%d", readLE32(blob[:4]))
	}
	if readLE32(blob[520:524]) != uint32(k.Private.E) {
		t.Fatal("wrong exponent")
	}
}

func TestQRSessionPNG(t *testing.T) {
	q, err := NewQRSession()
	if err != nil {
		t.Fatal(err)
	}
	if len(q.Payload) > 106 {
		t.Fatalf("payload too long: %d", len(q.Payload))
	}
	png, err := q.PNG(512)
	if err != nil {
		t.Fatal(err)
	}
	if len(png) < 100 {
		t.Fatal("PNG suspiciously small")
	}
	if !bytes.HasPrefix(png, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatal("not a PNG")
	}
}

func TestPairCipherDuplex(t *testing.T) {
	keyMaterial := bytes.Repeat([]byte{0x42}, 64)
	a, err := newPairCipher(keyMaterial)
	if err != nil {
		t.Fatal(err)
	}
	b, err := newPairCipher(keyMaterial)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := a.encrypt([]byte("client peer info"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := b.decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "client peer info" {
		t.Fatalf("got %q", pt)
	}
	ct, err = b.encrypt([]byte("server peer info"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err = a.decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "server peer info" {
		t.Fatalf("got %q", pt)
	}
}

func TestPacketRoundTrip(t *testing.T) {
	var b bytes.Buffer
	want := packet{command: cmdWRTE, arg0: 7, arg1: 11, data: []byte("hello")}
	if err := writePacket(&b, want); err != nil {
		t.Fatal(err)
	}
	got, err := readPacket(&b)
	if err != nil {
		t.Fatal(err)
	}
	if got.command != want.command || got.arg0 != want.arg0 || got.arg1 != want.arg1 || !bytes.Equal(got.data, want.data) {
		t.Fatalf("packet mismatch: %#v != %#v", got, want)
	}
}
