package adb

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"strings"
	"time"
)

type QRSession struct {
	ServiceName string
	Password    string
	Payload     string
}

func NewQRSession() (*QRSession, error) {
	name, err := randomText(10, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
	if err != nil {
		return nil, err
	}
	password, err := randomText(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+-./<=>?@[]^_{}~")
	if err != nil {
		return nil, err
	}
	service := "studio-" + name
	payload := fmt.Sprintf("WIFI:T:ADB;S:%s;P:%s;;", service, password)
	return &QRSession{ServiceName: service, Password: password, Payload: payload}, nil
}

// PNG returns a dependency-free QR Code (QR Version 5, error correction L).
// Version 5-L can hold up to 106 byte-mode bytes, more than enough for ADB's
// Wireless Debugging QR payload.
func (q *QRSession) PNG(size int) ([]byte, error) {
	if q == nil || q.Payload == "" {
		return nil, errors.New("adb: invalid QR session")
	}
	matrix, err := encodeQR5L([]byte(q.Payload))
	if err != nil {
		return nil, err
	}
	if size <= 0 {
		size = 512
	}
	if size < 45 {
		size = 45
	}
	img := image.NewGray(image.Rect(0, 0, size, size))
	draw.Draw(img, img.Bounds(), &image.Uniform{C: color.White}, image.Point{}, draw.Src)
	modules := len(matrix)
	quiet := 4
	total := modules + quiet*2
	scale := size / total
	if scale < 1 {
		scale = 1
	}
	actual := total * scale
	offset := (size-actual)/2 + quiet*scale
	for y := 0; y < modules; y++ {
		for x := 0; x < modules; x++ {
			if !matrix[y][x] {
				continue
			}
			r := image.Rect(offset+x*scale, offset+y*scale, offset+(x+1)*scale, offset+(y+1)*scale)
			draw.Draw(img, r, &image.Uniform{C: color.Black}, image.Point{}, draw.Src)
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (q *QRSession) SVG(moduleSize int) ([]byte, error) {
	if q == nil || q.Payload == "" {
		return nil, errors.New("adb: invalid QR session")
	}
	m, err := encodeQR5L([]byte(q.Payload))
	if err != nil {
		return nil, err
	}
	if moduleSize <= 0 {
		moduleSize = 8
	}
	quiet := 4
	sz := (len(m) + quiet*2) * moduleSize
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d"><rect width="100%%" height="100%%" fill="white"/><path fill="black" d="`, sz, sz, sz, sz)
	for y := range m {
		for x, on := range m[y] {
			if on {
				fmt.Fprintf(&b, "M%d %dh%dv%dh-%dz", (x+quiet)*moduleSize, (y+quiet)*moduleSize, moduleSize, moduleSize, moduleSize)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return []byte(b.String()), nil
}

func (q *QRSession) Pair(ctx context.Context, key *Key) (*PairResult, error) {
	if q == nil {
		return nil, errors.New("adb: nil QR session")
	}
	pairCtx, cancel := withDefaultTimeout(ctx, 2*time.Minute)
	defer cancel()
	ep, err := WaitPairingEndpoint(pairCtx, q.ServiceName)
	if err != nil {
		return nil, err
	}
	result, err := Pair(pairCtx, ep.Address(), q.Password, key)
	if err != nil {
		return nil, err
	}
	connectCtx, connectCancel := context.WithTimeout(ctx, 15*time.Second)
	defer connectCancel()
	if cep, err := WaitConnectEndpoint(connectCtx, result.GUID); err == nil {
		result.ConnectAddress = cep.Address()
	}
	return result, nil
}

func randomText(n int, alphabet string) (string, error) {
	if n <= 0 || len(alphabet) == 0 || len(alphabet) > 256 {
		return "", errors.New("adb: invalid random text parameters")
	}
	out := make([]byte, n)
	buf := make([]byte, n*2)
	written := 0
	limit := 256 - (256 % len(alphabet))
	for written < n {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, v := range buf {
			if int(v) >= limit {
				continue
			}
			out[written] = alphabet[int(v)%len(alphabet)]
			written++
			if written == n {
				break
			}
		}
	}
	return string(out), nil
}

// ---- Minimal QR Version 5-L encoder (byte mode, mask 0) ----

func encodeQR5L(data []byte) ([][]bool, error) {
	const version, size, dataCodewords, eccCodewords = 5, 37, 108, 26
	if len(data) > 106 {
		return nil, fmt.Errorf("adb: QR payload too long: %d bytes", len(data))
	}
	var bits []bool
	appendBits := func(v uint, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, ((v>>uint(i))&1) != 0)
		}
	}
	appendBits(0x4, 4) // byte mode
	appendBits(uint(len(data)), 8)
	for _, b := range data {
		appendBits(uint(b), 8)
	}
	for i := 0; i < 4 && len(bits) < dataCodewords*8; i++ {
		bits = append(bits, false)
	}
	for len(bits)%8 != 0 {
		bits = append(bits, false)
	}
	cw := make([]byte, 0, dataCodewords)
	for i := 0; i < len(bits); i += 8 {
		var v byte
		for j := 0; j < 8; j++ {
			if bits[i+j] {
				v |= 1 << uint(7-j)
			}
		}
		cw = append(cw, v)
	}
	for pad := 0; len(cw) < dataCodewords; pad++ {
		if pad%2 == 0 {
			cw = append(cw, 0xEC)
		} else {
			cw = append(cw, 0x11)
		}
	}
	ecc := qrRSRemainder(cw, qrRSDivisor(eccCodewords))
	codewords := append(append([]byte(nil), cw...), ecc...)

	mods := make([][]bool, size)
	fun := make([][]bool, size)
	for i := 0; i < size; i++ {
		mods[i] = make([]bool, size)
		fun[i] = make([]bool, size)
	}
	setf := func(x, y int, on bool) {
		if x >= 0 && x < size && y >= 0 && y < size {
			mods[y][x] = on
			fun[y][x] = true
		}
	}
	finder := func(cx, cy int) {
		for dy := -4; dy <= 4; dy++ {
			for dx := -4; dx <= 4; dx++ {
				d := abs(dx)
				if abs(dy) > d {
					d = abs(dy)
				}
				setf(cx+dx, cy+dy, d != 2 && d != 4)
			}
		}
	}
	finder(3, 3)
	finder(size-4, 3)
	finder(3, size-4)
	for i := 8; i < size-8; i++ {
		setf(6, i, i%2 == 0)
		setf(i, 6, i%2 == 0)
	}
	// Version 5 alignment pattern centers are 6 and 30; only (30,30) does not overlap a finder.
	for dy := -2; dy <= 2; dy++ {
		for dx := -2; dx <= 2; dx++ {
			d := abs(dx)
			if abs(dy) > d {
				d = abs(dy)
			}
			setf(30+dx, 30+dy, d != 1)
		}
	}
	format := qrFormatBits(1, 0) // ECL L = 01b, mask 0
	bit := func(i int) bool { return ((format >> uint(i)) & 1) != 0 }
	for i := 0; i <= 5; i++ {
		setf(8, i, bit(i))
	}
	setf(8, 7, bit(6))
	setf(8, 8, bit(7))
	setf(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		setf(14-i, 8, bit(i))
	}
	for i := 0; i < 8; i++ {
		setf(size-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		setf(8, size-15+i, bit(i))
	}
	setf(8, size-8, true)

	getBit := func(i int) bool {
		if i >= len(codewords)*8 {
			return false
		}
		return ((codewords[i>>3] >> uint(7-(i&7))) & 1) != 0
	}
	idx := 0
	for right := size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < size; vert++ {
			y := vert
			if ((right + 1) & 2) == 0 {
				y = size - 1 - vert
			}
			for j := 0; j < 2; j++ {
				x := right - j
				if fun[y][x] {
					continue
				}
				v := getBit(idx)
				idx++
				if (x+y)%2 == 0 {
					v = !v
				}
				mods[y][x] = v
			}
		}
	}
	_ = version
	return mods, nil
}

func qrFormatBits(ecl, mask int) uint16 {
	data := uint16((ecl << 3) | mask)
	rem := data
	for i := 0; i < 10; i++ {
		rem = (rem << 1) ^ uint16((int(rem>>9)&1)*0x537)
	}
	return (data<<10 | rem) ^ 0x5412
}

func qrRSDivisor(degree int) []byte {
	res := make([]byte, degree)
	res[degree-1] = 1
	root := byte(1)
	for i := 0; i < degree; i++ {
		for j := 0; j < len(res); j++ {
			res[j] = qrGFMultiply(res[j], root)
			if j+1 < len(res) {
				res[j] ^= res[j+1]
			}
		}
		root = qrGFMultiply(root, 2)
	}
	return res
}
func qrRSRemainder(data, divisor []byte) []byte {
	res := make([]byte, len(divisor))
	for _, b := range data {
		factor := b ^ res[0]
		copy(res, res[1:])
		res[len(res)-1] = 0
		for i, c := range divisor {
			res[i] ^= qrGFMultiply(c, factor)
		}
	}
	return res
}
func qrGFMultiply(x, y byte) byte {
	var z uint16
	a, b := uint16(x), uint16(y)
	for i := 7; i >= 0; i-- {
		z = (z << 1) ^ ((z >> 7) * 0x11D)
		if ((b >> uint(i)) & 1) != 0 {
			z ^= a
		}
	}
	return byte(z)
}
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
