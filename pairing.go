package adb

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	pairingVersion        = 1
	pairingTypeSPAKE2     = 0
	pairingTypePeerInfo   = 1
	pairingPeerInfoSize   = 8192
	pairingMaxPayload     = 2 * pairingPeerInfoSize
	pairingTLSExportLabel = "adb-label"
)

type PairResult struct {
	GUID           string
	PairingAddress string
	ConnectAddress string
	PeerInfo       []byte
}

// Pair performs Android 11+ Wireless Debugging pairing against a discovered
// _adb-tls-pairing._tcp endpoint using the 6-digit pairing code or QR secret.
func Pair(ctx context.Context, address, secret string, key *Key) (*PairResult, error) {
	if key == nil || key.Private == nil {
		return nil, errors.New("adb: a persistent RSA key is required for pairing")
	}
	if secret == "" {
		return nil, errors.New("adb: empty pairing secret")
	}

	d := net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	applyContextDeadline(ctx, raw)

	cert, err := key.tlsCertificate()
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(raw, &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // ADB pairing intentionally accepts the peer's self-signed cert.
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("adb: pairing TLS handshake: %w", err)
	}

	state := tlsConn.ConnectionState()
	exported, err := state.ExportKeyingMaterial(pairingTLSExportLabel, nil, 64)
	if err != nil {
		return nil, fmt.Errorf("adb: TLS exporter: %w", err)
	}
	password := make([]byte, 0, len(secret)+len(exported))
	password = append(password, []byte(secret)...)
	password = append(password, exported...)

	spake, err := newSpake2(spakeAlice, password)
	if err != nil {
		return nil, err
	}
	if err := writePairingPacket(tlsConn, pairingTypeSPAKE2, spake.Message()); err != nil {
		return nil, err
	}
	typeID, peerSPAKE, err := readPairingPacket(tlsConn)
	if err != nil {
		return nil, err
	}
	if typeID != pairingTypeSPAKE2 {
		return nil, fmt.Errorf("%w: expected SPAKE2 packet, got type %d", ErrPairingFailed, typeID)
	}
	keyMaterial, err := spake.Finish(peerSPAKE)
	if err != nil {
		return nil, fmt.Errorf("%w: SPAKE2: %v", ErrPairingFailed, err)
	}
	cipher, err := newPairCipher(keyMaterial)
	if err != nil {
		return nil, err
	}

	pub, err := key.PublicKeyADB()
	if err != nil {
		return nil, err
	}
	ourPeerInfo := make([]byte, pairingPeerInfoSize)
	ourPeerInfo[0] = 0 // ADB_RSA_PUB_KEY
	if len(pub) > pairingPeerInfoSize-2 {
		return nil, errors.New("adb: public key does not fit PairingPeerInfo")
	}
	copy(ourPeerInfo[1:], pub)

	encrypted, err := cipher.encrypt(ourPeerInfo)
	if err != nil {
		return nil, err
	}
	if err := writePairingPacket(tlsConn, pairingTypePeerInfo, encrypted); err != nil {
		return nil, err
	}

	typeID, encryptedPeer, err := readPairingPacket(tlsConn)
	if err != nil {
		return nil, err
	}
	if typeID != pairingTypePeerInfo {
		return nil, fmt.Errorf("%w: expected PeerInfo packet, got type %d", ErrPairingFailed, typeID)
	}
	peerInfo, err := cipher.decrypt(encryptedPeer)
	if err != nil {
		return nil, fmt.Errorf("%w: authentication tag mismatch (wrong code/secret?): %v", ErrPairingFailed, err)
	}
	if len(peerInfo) != pairingPeerInfoSize {
		return nil, fmt.Errorf("%w: invalid PeerInfo size %d", ErrPairingFailed, len(peerInfo))
	}
	if peerInfo[0] != 1 { // ADB_DEVICE_GUID
		return nil, fmt.Errorf("%w: expected device GUID PeerInfo, got type %d", ErrPairingFailed, peerInfo[0])
	}
	guid := strings.TrimRight(string(peerInfo[1:]), "\x00")
	if guid == "" {
		return nil, fmt.Errorf("%w: device returned an empty GUID", ErrPairingFailed)
	}
	return &PairResult{GUID: guid, PairingAddress: address, PeerInfo: append([]byte(nil), peerInfo...)}, nil
}

func writePairingPacket(w io.Writer, typeID byte, payload []byte) error {
	if len(payload) > pairingMaxPayload {
		return fmt.Errorf("adb: pairing payload too large: %d", len(payload))
	}
	header := make([]byte, 6)
	header[0] = pairingVersion
	header[1] = typeID
	binary.BigEndian.PutUint32(header[2:6], uint32(len(payload)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readPairingPacket(r io.Reader) (byte, []byte, error) {
	header := make([]byte, 6)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	if header[0] != pairingVersion {
		return 0, nil, fmt.Errorf("adb: unsupported pairing protocol version %d", header[0])
	}
	n := binary.BigEndian.Uint32(header[2:6])
	if n > pairingMaxPayload {
		return 0, nil, fmt.Errorf("adb: pairing packet too large: %d", n)
	}
	payload := make([]byte, int(n))
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return header[1], payload, nil
}

func applyContextDeadline(ctx context.Context, c net.Conn) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
}

func withDefaultTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, d)
}
