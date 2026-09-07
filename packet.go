package adb

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	cmdSYNC = 0x434e5953
	cmdCNXN = 0x4e584e43
	cmdOPEN = 0x4e45504f
	cmdOKAY = 0x59414b4f
	cmdCLSE = 0x45534c43
	cmdWRTE = 0x45545257
	cmdAUTH = 0x48545541
	cmdSTLS = 0x534c5453

	adbVersion      = 0x01000001
	adbTLSVersion   = 0x01000000
	adbMaxPayload   = 1024 * 1024
	adbMaxPayloadV1 = 4096

	authToken     = 1
	authSignature = 2
	authPublicKey = 3
)

type packet struct {
	command uint32
	arg0    uint32
	arg1    uint32
	data    []byte
}

func writePacket(w io.Writer, p packet) error {
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:4], p.command)
	binary.LittleEndian.PutUint32(header[4:8], p.arg0)
	binary.LittleEndian.PutUint32(header[8:12], p.arg1)
	binary.LittleEndian.PutUint32(header[12:16], uint32(len(p.data)))
	binary.LittleEndian.PutUint32(header[16:20], adbChecksum(p.data))
	binary.LittleEndian.PutUint32(header[20:24], p.command^0xffffffff)
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(p.data) != 0 {
		_, err := w.Write(p.data)
		return err
	}
	return nil
}

func readPacket(r io.Reader) (packet, error) {
	var p packet
	header := make([]byte, 24)
	if _, err := io.ReadFull(r, header); err != nil {
		return p, err
	}
	p.command = binary.LittleEndian.Uint32(header[0:4])
	p.arg0 = binary.LittleEndian.Uint32(header[4:8])
	p.arg1 = binary.LittleEndian.Uint32(header[8:12])
	n := binary.LittleEndian.Uint32(header[12:16])
	check := binary.LittleEndian.Uint32(header[16:20])
	magic := binary.LittleEndian.Uint32(header[20:24])
	if magic != p.command^0xffffffff {
		return p, fmt.Errorf("%w: bad packet magic", ErrProtocol)
	}
	if n > adbMaxPayload {
		return p, fmt.Errorf("%w: payload too large: %d", ErrProtocol, n)
	}
	if n > 0 {
		p.data = make([]byte, int(n))
		if _, err := io.ReadFull(r, p.data); err != nil {
			return p, err
		}
	}
	// Modern ADB can skip checksums (check == 0). Validate whenever one is supplied.
	if check != 0 && check != adbChecksum(p.data) {
		return p, fmt.Errorf("%w: bad payload checksum", ErrProtocol)
	}
	return p, nil
}

func adbChecksum(data []byte) uint32 {
	var sum uint32
	for _, b := range data {
		sum += uint32(b)
	}
	return sum
}

func commandString(v uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return string(b[:])
}
