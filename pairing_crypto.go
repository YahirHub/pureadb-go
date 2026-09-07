package adb

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const pairingAESInfo = "adb pairing_auth aes-128-gcm key"

type pairCipher struct {
	aead   cipher.AEAD
	encSeq uint64
	decSeq uint64
}

func newPairCipher(keyMaterial []byte) (*pairCipher, error) {
	key := hkdfSHA256(keyMaterial, nil, []byte(pairingAESInfo), 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &pairCipher{aead: aead}, nil
}

func (p *pairCipher) encrypt(plain []byte) ([]byte, error) {
	if p == nil || p.aead == nil {
		return nil, errors.New("adb: nil pairing cipher")
	}
	nonce := make([]byte, p.aead.NonceSize())
	binary.LittleEndian.PutUint64(nonce, p.encSeq)
	p.encSeq++
	return p.aead.Seal(nil, nonce, plain, nil), nil
}

func (p *pairCipher) decrypt(ciphertext []byte) ([]byte, error) {
	if p == nil || p.aead == nil {
		return nil, errors.New("adb: nil pairing cipher")
	}
	nonce := make([]byte, p.aead.NonceSize())
	binary.LittleEndian.PutUint64(nonce, p.decSeq)
	p.decSeq++
	return p.aead.Open(nil, nonce, ciphertext, nil)
}

func hkdfSHA256(secret, salt, info []byte, length int) []byte {
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}
	extract := hmac.New(sha256.New, salt)
	_, _ = extract.Write(secret)
	prk := extract.Sum(nil)

	out := make([]byte, 0, length)
	var prev []byte
	for counter := byte(1); len(out) < length; counter++ {
		expand := hmac.New(sha256.New, prk)
		_, _ = expand.Write(prev)
		_, _ = expand.Write(info)
		_, _ = expand.Write([]byte{counter})
		prev = expand.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length]
}
