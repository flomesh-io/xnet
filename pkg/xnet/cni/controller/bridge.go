package controller

import (
	"net"
	"strings"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
	"github.com/flomesh-io/xnet/pkg/xnet/util"
)

func (s *server) getBridgeAddrs(br string) (int, []net.IP, net.HardwareAddr, error) {
	if br, err := net.InterfaceByName(br); err != nil {
		return -1, nil, nil, err
	} else if addrs, addrErr := br.Addrs(); addrErr == nil {
		var brAddrs []net.IP
		for _, addr := range addrs {
			addrStr := addr.String()
			addrStr = addrStr[0:strings.Index(addrStr, `/`)]
			brAddr := net.ParseIP(addrStr)
			if (brAddr.To4() == nil && brAddr.To16() == nil) || brAddr.IsUnspecified() || brAddr.IsMulticast() {
				continue
			}
			brAddrs = append(brAddrs, brAddr)
		}
		return br.Index, brAddrs, br.HardwareAddr, nil
	} else {
		return -1, nil, nil, addrErr
	}
}

func (s *server) loadBridges() {
	for _, br := range s.cniBridges {
		ifi, brAddrs, hwAddr, err := s.getBridgeAddrs(br.Name)
		if err != nil {
			log.Fatal().Err(err).Msgf(`invalid bridge eth: %s`, br.Name)
		} else {
			brKey := new(maps.IFaceKey)
			brKey.Len = uint8(len(br.Name))
			copy(brKey.Name[0:brKey.Len], br.Name)
			brVal := new(maps.IFaceVal)
			brVal.Ifi = uint32(ifi)
			if len(br.HardwareAddr) > 0 {
				copy(brVal.Mac[:], br.HardwareAddr[:])
			} else {
				copy(brVal.Mac[:], hwAddr[:])
			}
			copy(brVal.Xmac[:], hwAddr[:])
			for _, brAddr := range brAddrs {
				if brVal.Addr[0], brVal.Addr[1], brVal.Addr[2], brVal.Addr[3], _, err = util.IPToInt(brAddr); err == nil {
					break
				} else {
					continue
				}
			}
			if err := maps.AddIFaceEntry(brKey, brVal); err != nil {
				log.Fatal().Err(err).Msgf(`failed to add iface: %s`, brKey.String())
			}
		}
	}
}
