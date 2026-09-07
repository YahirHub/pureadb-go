package adb

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestMDNSParser(t *testing.T) {
	service := "_adb-tls-pairing._tcp.local"
	instance := "studio-AbCdEf1234." + service
	host := "pixel.local"
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[2:4], 0x8400)
	binary.BigEndian.PutUint16(msg[6:8], 4)
	addRR := func(name string, typ uint16, rdata []byte) {
		n, _ := encodeDNSName(name)
		msg = append(msg, n...)
		var hdr [10]byte
		binary.BigEndian.PutUint16(hdr[0:2], typ)
		binary.BigEndian.PutUint16(hdr[2:4], 1)
		binary.BigEndian.PutUint32(hdr[4:8], 120)
		binary.BigEndian.PutUint16(hdr[8:10], uint16(len(rdata)))
		msg = append(msg, hdr[:]...)
		msg = append(msg, rdata...)
	}
	ptr, _ := encodeDNSName(instance)
	addRR(service, 12, ptr)
	target, _ := encodeDNSName(host)
	srv := make([]byte, 6)
	binary.BigEndian.PutUint16(srv[4:6], 37123)
	srv = append(srv, target...)
	addRR(instance, 33, srv)
	addRR(instance, 16, append([]byte{3}, []byte("a=b")...))
	addRR(host, 1, []byte{192, 168, 1, 42})

	s := newMDNSState(service)
	s.addPacket(msg)
	eps := s.endpoints()
	if len(eps) != 1 {
		t.Fatalf("endpoints=%d", len(eps))
	}
	if eps[0].Instance != "studio-AbCdEf1234" {
		t.Fatalf("instance=%q", eps[0].Instance)
	}
	if eps[0].Port != 37123 || !eps[0].IP.Equal(net.IPv4(192, 168, 1, 42)) {
		t.Fatalf("endpoint=%+v", eps[0])
	}
}
