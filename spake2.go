package adb

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/big"

	"github.com/example/pureadb/internal/edwards25519"
)

type spakeRole uint8

const (
	spakeAlice spakeRole = iota
	spakeBob
)

var (
	spakeMEncoded = mustHex32("5ada7e4bf6ddd9adb6626d32131c6b5c51a1e347a3478f53cfcf441b88eed12e")
	spakeNEncoded = mustHex32("10e3df0ae37d8e7a99b5fe74b44672103dbddcbd06af680d71329a11693bc778")
	curveOrder    = mustBig("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)
)

type spake2State struct {
	role         spakeRole
	passwordHash [64]byte
	private      [32]byte
	myMsg        [32]byte
	myName       []byte
	theirName    []byte
}

func newSpake2(role spakeRole, password []byte) (*spake2State, error) {
	var rnd [64]byte
	if _, err := io.ReadFull(rand.Reader, rnd[:]); err != nil {
		return nil, err
	}

	s := &spake2State{role: role, passwordHash: sha512.Sum512(password)}
	if role == spakeAlice {
		s.myName = []byte("adb pair client\x00")
		s.theirName = []byte("adb pair server\x00")
	} else {
		s.myName = []byte("adb pair server\x00")
		s.theirName = []byte("adb pair client\x00")
	}

	privScalar, err := new(edwards25519.Scalar).SetUniformBytes(rnd[:])
	if err != nil {
		return nil, err
	}
	// BoringSSL SPAKE2 multiplies the private scalar by the cofactor (8)
	// without reducing it modulo the subgroup order.
	privInt := littleToBig(privScalar.Bytes())
	privInt.Lsh(privInt, 3)
	copy(s.private[:], bigToLittleFixed(privInt, 32))

	base := edwards25519.NewGeneratorPoint()
	p := scalarMultArbitrary(base, s.private[:])

	pwScalar, err := new(edwards25519.Scalar).SetUniformBytes(s.passwordHash[:])
	if err != nil {
		return nil, err
	}
	pw := passwordScalarHack(pwScalar.Bytes())

	maskBytes := spakeMEncoded[:]
	if role == spakeBob {
		maskBytes = spakeNEncoded[:]
	}
	maskPoint, err := new(edwards25519.Point).SetBytes(maskBytes)
	if err != nil {
		return nil, err
	}
	masked := scalarMultArbitrary(maskPoint, pw)
	msg := new(edwards25519.Point).Add(p, masked)
	copy(s.myMsg[:], msg.Bytes())
	return s, nil
}

func (s *spake2State) Message() []byte {
	return append([]byte(nil), s.myMsg[:]...)
}

func (s *spake2State) Finish(peerMsg []byte) ([]byte, error) {
	if len(peerMsg) != 32 {
		return nil, errors.New("adb: invalid SPAKE2 peer message length")
	}
	peer, err := new(edwards25519.Point).SetBytes(peerMsg)
	if err != nil {
		return nil, err
	}
	pwScalar, err := new(edwards25519.Scalar).SetUniformBytes(s.passwordHash[:])
	if err != nil {
		return nil, err
	}
	pw := passwordScalarHack(pwScalar.Bytes())

	maskBytes := spakeNEncoded[:]
	if s.role == spakeBob {
		maskBytes = spakeMEncoded[:]
	}
	maskPoint, err := new(edwards25519.Point).SetBytes(maskBytes)
	if err != nil {
		return nil, err
	}
	mask := scalarMultArbitrary(maskPoint, pw)
	unmasked := new(edwards25519.Point).Subtract(peer, mask)
	shared := scalarMultArbitrary(unmasked, s.private[:])
	sharedBytes := shared.Bytes()

	h := sha512.New()
	if s.role == spakeAlice {
		writeTranscript(h, s.myName)
		writeTranscript(h, s.theirName)
		writeTranscript(h, s.myMsg[:])
		writeTranscript(h, peerMsg)
	} else {
		writeTranscript(h, s.theirName)
		writeTranscript(h, s.myName)
		writeTranscript(h, peerMsg)
		writeTranscript(h, s.myMsg[:])
	}
	writeTranscript(h, sharedBytes)
	writeTranscript(h, s.passwordHash[:])
	return h.Sum(nil), nil
}

func writeTranscript(w io.Writer, data []byte) {
	var n [8]byte
	binary.LittleEndian.PutUint64(n[:], uint64(len(data)))
	_, _ = w.Write(n[:])
	_, _ = w.Write(data)
}

// passwordScalarHack mirrors BoringSSL's SPAKE2 compatibility behavior: the
// reduced password scalar is adjusted by multiples of l until it is divisible
// by 8, deliberately without a final reduction.
func passwordScalarHack(canonical []byte) []byte {
	n := littleToBig(canonical)
	if n.Bit(0) != 0 {
		n.Add(n, curveOrder)
	}
	if n.Bit(1) != 0 {
		n.Add(n, new(big.Int).Lsh(new(big.Int).Set(curveOrder), 1))
	}
	if n.Bit(2) != 0 {
		n.Add(n, new(big.Int).Lsh(new(big.Int).Set(curveOrder), 2))
	}
	return bigToLittleFixed(n, 32)
}

// scalarMultArbitrary performs scalar multiplication using the full 256-bit
// integer rather than edwards25519.Scalar. This is required for SPAKE2's
// historical small-order-point compatibility behavior in BoringSSL.
func scalarMultArbitrary(p *edwards25519.Point, scalarLE []byte) *edwards25519.Point {
	result := edwards25519.NewIdentityPoint()
	addend := new(edwards25519.Point).Set(p)
	for i := 0; i < len(scalarLE)*8; i++ {
		if (scalarLE[i/8] & (1 << uint(i%8))) != 0 {
			result.Add(result, addend)
		}
		addend.Add(addend, addend)
	}
	return result
}

func mustHex32(s string) [32]byte {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		panic("invalid 32-byte hex constant")
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func mustBig(s string, base int) *big.Int {
	n, ok := new(big.Int).SetString(s, base)
	if !ok {
		panic("invalid big integer constant")
	}
	return n
}

func littleToBig(le []byte) *big.Int {
	be := make([]byte, len(le))
	for i := range le {
		be[len(le)-1-i] = le[i]
	}
	return new(big.Int).SetBytes(be)
}

func bigToLittleFixed(n *big.Int, size int) []byte {
	be := n.Bytes()
	out := make([]byte, size)
	for i := 0; i < len(be) && i < size; i++ {
		out[i] = be[len(be)-1-i]
	}
	return out
}
