package route

import (
	"net"
)

func discoverGatewayOSSpecific() (string, net.IP, error) {
	return "", nil, &ErrNotImplemented{}
}

func GetDefaultGatewayAddr(iface net.Interface) (net.IP, error) {
	panic("Unsupported!")
}
