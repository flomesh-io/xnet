package controller

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/flomesh-io/xnet/pkg/xnet/ns"
	"github.com/flomesh-io/xnet/pkg/xnet/volume"
)

func (s *server) findHwAddrByPodIP(podIP string) (net.HardwareAddr, bool) {
	rd, err := os.ReadDir(volume.Netns.MountPath)
	if err != nil {
		log.Error().Err(err).Msg(volume.Netns.MountPath)
		return nil, false
	}

	var hwAddr net.HardwareAddr
	for _, fi := range rd {
		if fi.IsDir() {
			continue
		}
		inode := fmt.Sprintf(`%s/%s`, volume.Netns.MountPath, fi.Name())
		netNS, nsErr := ns.GetNS(inode)
		if nsErr != nil {
			log.Error().Err(nsErr).Msg(inode)
			continue
		}

		if nsErr = netNS.Do(func(_ ns.NetNS) error {
			ifaces, ifaceErr := net.Interfaces()
			if ifaceErr != nil {
				return ifaceErr
			}
			for _, iface := range ifaces {
				if (iface.Flags&net.FlagLoopback) == 0 && (iface.Flags&net.FlagUp) != 0 {
					if addrs, addrErr := iface.Addrs(); addrErr == nil {
						for _, addr := range addrs {
							addrStr := addr.String()
							addrStr = addrStr[0:strings.Index(addrStr, `/`)]
							if strings.EqualFold(addrStr, podIP) {
								hwAddr = iface.HardwareAddr
								return nil
							}
						}
					}
				}
			}
			return nil
		}); nsErr != nil {
			log.Error().Err(nsErr).Msg(inode)
		}
	}
	return hwAddr, hwAddr != nil
}
