package controller

import (
	"net"
	"strings"
)

func (s *server) getBridgeAddrs(br string) (int, []net.IP, net.HardwareAddr, error) {
	if br, err := net.InterfaceByName(br); err != nil {
		return -1, nil, nil, err
	} else if addrs, addrErr := br.Addrs(); addrErr == nil {
		var brAddrs []net.IP
		for _, addr := range addrs {
			addrStr := addr.String()
			if strings.Index(addrStr, `:`) > 0 {
				continue
			}
			addrStr = addrStr[0:strings.Index(addrStr, `/`)]
			brAddr := net.ParseIP(addrStr)
			if brAddr.To4() == nil || brAddr.IsUnspecified() || brAddr.IsMulticast() {
				continue
			}
			brAddrs = append(brAddrs, brAddr)
		}
		return br.Index, brAddrs, br.HardwareAddr, nil
	} else {
		return -1, nil, nil, addrErr
	}
}
