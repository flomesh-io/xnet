package controller

import (
	"net"
	"os"
	"strings"

	"github.com/flomesh-io/xnet/pkg/xnet/ns"
	"github.com/flomesh-io/xnet/pkg/xnet/volume"
)

func (s *server) findHwAddrByPodIP(podIP string) (net.HardwareAddr, bool) {
	var hwAddr net.HardwareAddr
	netnsDirs := []string{volume.Netns.MountPath, volume.SysProc.MountPath}
	for _, netnsDir := range netnsDirs {
		rd, err := os.ReadDir(netnsDir)
		if err != nil {
			log.Debug().Err(err).Msg(netnsDir)
			continue
		}
		for _, fi := range rd {
			nsName, inode := ns.GetInode(fi, netnsDir)
			netNS, nsErr := ns.GetNS(inode)
			if nsErr != nil {
				log.Debug().Err(nsErr).Msg(nsName)
				continue
			}

			if nsErr = netNS.Do(func(_ ns.NetNS) error {
				ifaces, ifaceErr := net.Interfaces()
				if ifaceErr != nil {
					log.Debug().Err(ifaceErr).Msg(nsName)
					return nil
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
				log.Debug().Err(nsErr).Msg(nsName)
			}
		}
	}
	return hwAddr, hwAddr != nil
}
