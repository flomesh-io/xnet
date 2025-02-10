package util

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

var ErrInvalidIPAddress = errors.New("invalid ip address")
var ErrNotIPv4Address = errors.New("not an IPv4 address")
var ErrNotIPv6Address = errors.New("not an IPv6 address")

func IPToInt(ipaddr net.IP) (addr0, addr1, addr2, addr4 uint32, v6 uint8, err error) {
	if ipaddr.To4() != nil {
		addr0 = binary.LittleEndian.Uint32(ipaddr.To4())
		return
	}
	if v6Bytes := ipaddr.To16(); v6Bytes != nil {
		addr0 = binary.LittleEndian.Uint32(v6Bytes[0:4])
		addr1 = binary.LittleEndian.Uint32(v6Bytes[4:8])
		addr2 = binary.LittleEndian.Uint32(v6Bytes[8:12])
		addr4 = binary.LittleEndian.Uint32(v6Bytes[12:16])
		v6 = 1
		return
	}
	err = ErrInvalidIPAddress
	return
}

// IPv4ToInt converts IP address of version 4 from net.IP to uint32
// representation.
func IPv4ToInt(ipaddr net.IP) (uint32, error) {
	if ipaddr.To4() == nil {
		return 0, ErrNotIPv4Address
	}
	return binary.LittleEndian.Uint32(ipaddr.To4()), nil
}

// IPv6ToInt4 converts IP address of version 6 from net.IP to [4]uint32
// representation.
func IPv6ToInt4(ipaddr net.IP) ([4]uint32, error) {
	v6Bytes := ipaddr.To16()
	if v6Bytes == nil {
		return [4]uint32{0, 0, 0, 0}, ErrNotIPv6Address
	}
	v6Ints := [4]uint32{}
	v6Ints[0] = binary.LittleEndian.Uint32(v6Bytes[0:4])
	v6Ints[1] = binary.LittleEndian.Uint32(v6Bytes[4:8])
	v6Ints[2] = binary.LittleEndian.Uint32(v6Bytes[8:12])
	v6Ints[3] = binary.LittleEndian.Uint32(v6Bytes[12:16])
	return v6Ints, nil
}

// IntToIPv4 converts IP address of version 4 from uint32 to net.IP
// representation.
func IntToIPv4(ipaddr uint32) net.IP {
	ip := make(net.IP, net.IPv4len)
	// Proceed conversion
	binary.LittleEndian.PutUint32(ip, ipaddr)
	return ip
}

// Int4ToIPv6 converts IP address of version 6 from [4]uint32 to net.IP
// representation.
func Int4ToIPv6(v6Ints [4]uint32) net.IP {
	ip := make(net.IP, net.IPv6len)
	// Proceed conversion
	binary.LittleEndian.PutUint32(ip[0:], v6Ints[0])
	binary.LittleEndian.PutUint32(ip[4:], v6Ints[1])
	binary.LittleEndian.PutUint32(ip[8:], v6Ints[2])
	binary.LittleEndian.PutUint32(ip[12:], v6Ints[3])
	return ip
}

// ParseIP implements extension of net.ParseIP. It returns additional
// information about IP address bytes length. In general, it works typically
// as standard net.ParseIP. So if IP is not valid, nil is returned.
func ParseIP(s string) (net.IP, int, error) {
	pip := net.ParseIP(s)
	if pip == nil {
		return nil, 0, ErrInvalidIPAddress
	} else if strings.Contains(s, ".") {
		return pip, 4, nil
	}
	return pip, 16, nil
}

// NetToHostShort converts a 16-bit integer from network to host byte order, aka "ntohs"
func NetToHostShort(i uint16) uint16 {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, i)
	return binary.LittleEndian.Uint16(data)
}

// NetToHostLong converts a 32-bit integer from network to host byte order, aka "ntohl"
func NetToHostLong(i uint32) uint32 {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, i)
	return binary.LittleEndian.Uint32(data)
}

// HostToNetShort converts a 16-bit integer from host to network byte order, aka "htons"
func HostToNetShort(i uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, i)
	return binary.BigEndian.Uint16(b)
}

// HostToNetLong converts a 32-bit integer from host to network byte order, aka "htonl"
func HostToNetLong(i uint32) uint32 {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, i)
	return binary.BigEndian.Uint32(b)
}
