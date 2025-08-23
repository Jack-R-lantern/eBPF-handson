package netutil

import (
	"encoding/binary"
	"fmt"
	"net"
)

func IPv4ToU32(s string) (uint32, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return 0, fmt.Errorf("parse failed")
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("not IPv4")
	}
	return binary.BigEndian.Uint32(ip4), nil
}

func U32ToIPv4(n uint32) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	return net.IP(b[:]).String()
}
