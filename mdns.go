package adb

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	ServiceLegacyADB  = "_adb._tcp"
	ServicePairingADB = "_adb-tls-pairing._tcp"
	ServiceConnectADB = "_adb-tls-connect._tcp"
)

type Endpoint struct {
	Instance string
	Host     string
	IP       net.IP
	Port     int
	TXT      []string
}

func (e Endpoint) Address() string { return net.JoinHostPort(e.IP.String(), fmt.Sprintf("%d", e.Port)) }

// Discover performs dependency-free mDNS discovery. Queries are sent from an
// ephemeral UDP port (legacy-unicast mDNS), so Android responds directly and we
// don't need to own UDP/5353 or coexist with a system mDNS daemon.
func Discover(ctx context.Context, service string) (<-chan Endpoint, error) {
	if service == "" {
		return nil, errors.New("adb: empty mDNS service")
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	out := make(chan Endpoint, 16)
	go discoverMDNS(ctx, conn, service, out)
	return out, nil
}

func discoverMDNS(ctx context.Context, conn *net.UDPConn, service string, out chan<- Endpoint) {
	defer conn.Close()
	defer close(out)

	qname := strings.TrimSuffix(service, ".") + ".local"
	state := newMDNSState(qname)
	sent := map[string]string{}
	lastQuery := time.Time{}
	buf := make([]byte, 64*1024)

	for {
		if ctx.Err() != nil {
			return
		}
		if time.Since(lastQuery) >= 1500*time.Millisecond {
			q, err := buildMDNSQuery(qname)
			if err == nil {
				_, _ = conn.WriteToUDP(q, &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353})
			}
			lastQuery = time.Now()
		}
		_ = conn.SetReadDeadline(time.Now().Add(350 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		state.addPacket(buf[:n])
		for _, ep := range state.endpoints() {
			key := ep.Instance + "|" + ep.Address()
			fingerprint := ep.Host + "|" + strings.Join(ep.TXT, "\x00")
			if sent[key] == fingerprint {
				continue
			}
			sent[key] = fingerprint
			select {
			case out <- ep:
			case <-ctx.Done():
				return
			}
		}
	}
}

func WaitPairingEndpoint(ctx context.Context, serviceName string) (Endpoint, error) {
	return waitEndpoint(ctx, ServicePairingADB, func(e Endpoint) bool {
		return serviceName == "" || strings.EqualFold(e.Instance, serviceName)
	}, ErrPairingNotFound)
}

func WaitConnectEndpoint(ctx context.Context, guid string) (Endpoint, error) {
	return waitEndpoint(ctx, ServiceConnectADB, func(e Endpoint) bool {
		if guid == "" {
			return true
		}
		name, g := strings.ToLower(e.Instance), strings.ToLower(guid)
		return name == g || strings.Contains(name, g)
	}, ErrConnectNotFound)
}

func waitEndpoint(ctx context.Context, service string, match func(Endpoint) bool, notFound error) (Endpoint, error) {
	endpoints, err := Discover(ctx, service)
	if err != nil {
		return Endpoint{}, err
	}
	for {
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return Endpoint{}, notFound
			}
			return Endpoint{}, ctx.Err()
		case ep, ok := <-endpoints:
			if !ok {
				return Endpoint{}, notFound
			}
			if match(ep) {
				return ep, nil
			}
		}
	}
}

func buildMDNSQuery(name string) ([]byte, error) {
	encoded, err := encodeDNSName(name)
	if err != nil {
		return nil, err
	}
	q := make([]byte, 12, 12+len(encoded)+4)
	var id [2]byte
	_, _ = rand.Read(id[:])
	copy(q[0:2], id[:])
	binary.BigEndian.PutUint16(q[4:6], 1) // QDCOUNT
	q = append(q, encoded...)
	var tail [4]byte
	binary.BigEndian.PutUint16(tail[0:2], 12)     // PTR
	binary.BigEndian.PutUint16(tail[2:4], 0x8001) // IN + QU (unicast response requested)
	q = append(q, tail[:]...)
	return q, nil
}

func encodeDNSName(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	var out []byte
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, errors.New("adb: invalid DNS label")
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	return out, nil
}

type mdnsSRV struct {
	host string
	port int
}
type mdnsState struct {
	service   string
	instances map[string]bool
	srv       map[string]mdnsSRV
	txt       map[string][]string
	ips       map[string][]net.IP
}

func newMDNSState(service string) *mdnsState {
	return &mdnsState{service: strings.ToLower(strings.TrimSuffix(service, ".")), instances: map[string]bool{}, srv: map[string]mdnsSRV{}, txt: map[string][]string{}, ips: map[string][]net.IP{}}
}

func (s *mdnsState) addPacket(msg []byte) {
	if len(msg) < 12 {
		return
	}
	off := 12
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	ns := int(binary.BigEndian.Uint16(msg[8:10]))
	ar := int(binary.BigEndian.Uint16(msg[10:12]))
	for i := 0; i < qd; i++ {
		_, next, ok := decodeDNSName(msg, off, 0)
		if !ok || next+4 > len(msg) {
			return
		}
		off = next + 4
	}
	for i := 0; i < an+ns+ar; i++ {
		name, next, ok := decodeDNSName(msg, off, 0)
		if !ok || next+10 > len(msg) {
			return
		}
		typ := binary.BigEndian.Uint16(msg[next : next+2])
		rdlen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
		rdata := next + 10
		end := rdata + rdlen
		if end > len(msg) {
			return
		}
		owner := strings.ToLower(strings.TrimSuffix(name, "."))
		switch typ {
		case 12: // PTR
			target, _, ok := decodeDNSName(msg, rdata, 0)
			if ok && owner == s.service {
				s.instances[strings.TrimSuffix(target, ".")] = true
			}
		case 33: // SRV
			if rdlen >= 6 {
				host, _, ok := decodeDNSName(msg, rdata+6, 0)
				if ok {
					s.srv[strings.TrimSuffix(name, ".")] = mdnsSRV{host: strings.TrimSuffix(host, "."), port: int(binary.BigEndian.Uint16(msg[rdata+4 : rdata+6]))}
				}
			}
		case 16: // TXT
			var vals []string
			for p := rdata; p < end; {
				n := int(msg[p])
				p++
				if p+n > end {
					break
				}
				vals = append(vals, string(msg[p:p+n]))
				p += n
			}
			s.txt[strings.TrimSuffix(name, ".")] = vals
		case 1: // A
			if rdlen == 4 {
				s.ips[strings.TrimSuffix(name, ".")] = appendUniqueIP(s.ips[strings.TrimSuffix(name, ".")], net.IPv4(msg[rdata], msg[rdata+1], msg[rdata+2], msg[rdata+3]))
			}
		case 28: // AAAA
			if rdlen == 16 {
				s.ips[strings.TrimSuffix(name, ".")] = appendUniqueIP(s.ips[strings.TrimSuffix(name, ".")], net.IP(append([]byte(nil), msg[rdata:end]...)))
			}
		}
		off = end
	}
}

func (s *mdnsState) endpoints() []Endpoint {
	var out []Endpoint
	serviceSuffix := "." + s.service
	for full := range s.instances {
		srv, ok := s.srv[full]
		if !ok {
			continue
		}
		ips := s.ips[srv.host]
		for _, ip := range ips {
			instance := strings.TrimSuffix(strings.ToLower(full), serviceSuffix)
			// Preserve original case where possible.
			orig := strings.TrimSuffix(full, ".")
			if len(orig) > len(serviceSuffix) {
				instance = orig[:len(orig)-len(serviceSuffix)]
			}
			out = append(out, Endpoint{Instance: instance, Host: srv.host, IP: append(net.IP(nil), ip...), Port: srv.port, TXT: append([]string(nil), s.txt[full]...)})
		}
	}
	return out
}

func appendUniqueIP(list []net.IP, ip net.IP) []net.IP {
	for _, x := range list {
		if x.Equal(ip) {
			return list
		}
	}
	return append(list, append(net.IP(nil), ip...))
}

func decodeDNSName(msg []byte, off int, depth int) (string, int, bool) {
	if depth > 16 || off < 0 || off >= len(msg) {
		return "", off, false
	}
	var labels []string
	next := off
	jumped := false
	for {
		if off >= len(msg) {
			return "", next, false
		}
		b := msg[off]
		if b&0xC0 == 0xC0 {
			if off+1 >= len(msg) {
				return "", next, false
			}
			ptr := int(b&0x3F)<<8 | int(msg[off+1])
			if !jumped {
				next = off + 2
				jumped = true
			}
			tail, _, ok := decodeDNSName(msg, ptr, depth+1)
			if !ok {
				return "", next, false
			}
			if tail != "" {
				labels = append(labels, tail)
			}
			break
		}
		off++
		if b == 0 {
			if !jumped {
				next = off
			}
			break
		}
		if b > 63 || off+int(b) > len(msg) {
			return "", next, false
		}
		labels = append(labels, string(msg[off:off+int(b)]))
		off += int(b)
		if !jumped {
			next = off
		}
	}
	return strings.Join(labels, "."), next, true
}
