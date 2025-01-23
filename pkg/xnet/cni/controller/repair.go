package controller

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
	"github.com/flomesh-io/xnet/pkg/xnet/ns"
	"github.com/flomesh-io/xnet/pkg/xnet/tc"
	"github.com/flomesh-io/xnet/pkg/xnet/volume"
)

func (s *server) CheckAndRepairPods() {
	var repairFailPods map[string]string
	for {
		repairFailPods = s.doCheckAndRepairPods()
		if len(repairFailPods) == 0 {
			break
		}
		for _, pod := range repairFailPods {
			log.Error().Msgf(`fail to check and repair pod: %s`, pod)
		}
		time.Sleep(time.Second * 3)
	}
}

func (s *server) doCheckAndRepairPods() map[string]string {
	monitoredPodsByAddr := make(map[string]string)
	pods := s.kubeController.ListMonitoredPods()
	for _, pod := range pods {
		monitoredPodsByAddr[pod.Status.PodIP] = fmt.Sprintf(`%s/%s`, pod.Namespace, pod.Name)
	}
	rd, err := os.ReadDir(volume.Netns.MountPath)
	if err != nil {
		log.Error().Err(err).Msg(volume.Netns.MountPath)
		return monitoredPodsByAddr
	}
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
							if pod, exists := monitoredPodsByAddr[addrStr]; exists {
								if attachErr := tc.AttachBPFProg(maps.SysMesh, iface.Name, true, true); attachErr != nil {
									return fmt.Errorf(`%s %s`, pod, attachErr.Error())
								}
								delete(monitoredPodsByAddr, addrStr)
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
	return monitoredPodsByAddr
}
