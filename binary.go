package adb

import "encoding/binary"

func putLE32(b []byte, v uint32) { binary.LittleEndian.PutUint32(b, v) }
func readLE32(b []byte) uint32   { return binary.LittleEndian.Uint32(b) }
