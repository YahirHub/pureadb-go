package byteorder

import "encoding/binary"

func LeUint64(b []byte) uint64       { return binary.LittleEndian.Uint64(b) }
func LePutUint64(b []byte, v uint64) { binary.LittleEndian.PutUint64(b, v) }
