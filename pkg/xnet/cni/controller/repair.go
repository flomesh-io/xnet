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

func (s *server) checkAndRepairPods() {
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
	allPodsByAddr := make(map[string]string)
	monitoredPodsByAddr := make(map[string]string)
	pods := s.kubeController.ListMonitoredPods()
	for _, pod := range pods {
		monitoredPodsByAddr[pod.Status.PodIP] = fmt.Sprintf(`%s/%s`, pod.Namespace, pod.Name)
	}
	pods = s.kubeController.ListAllPods()
	for _, pod := range pods {
		allPodsByAddr[pod.Status.PodIP] = fmt.Sprintf(`%s/%s`, pod.Namespace, pod.Name)
	}

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

			if doErr := netNS.Do(func(_ ns.NetNS) error {
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
								if pod, exists := monitoredPodsByAddr[addrStr]; exists {
									if attachErr := tc.AttachBPFProg(maps.SysMesh, iface.Name, true, true); attachErr != nil {
										return fmt.Errorf(`%s %s`, pod, attachErr.Error())
									}
									delete(monitoredPodsByAddr, addrStr)
									delete(allPodsByAddr, addrStr)
								} else if pod, exists := allPodsByAddr[addrStr]; exists {
									if detachErr := tc.DetachBPFProg(maps.SysMesh, iface.Name, true, true); detachErr != nil {
										return fmt.Errorf(`%s %s`, pod, detachErr.Error())
									}
									delete(allPodsByAddr, addrStr)
								}
							}
						}
					}
				}
				return nil
			}); doErr != nil {
				log.Debug().Err(doErr).Msg(nsName)
			}
		}
	}
	return monitoredPodsByAddr
}

func (s *server) checkAndResetPods() {
	var resetFailPods map[string]string
	for {
		resetFailPods = s.doCheckAndResetPods()
		if len(resetFailPods) == 0 {
			break
		}
		for _, pod := range resetFailPods {
			log.Error().Msgf(`fail to check and reset pod: %s`, pod)
		}
		time.Sleep(time.Second * 3)
	}
}

func (s *server) doCheckAndResetPods() map[string]string {
	allPodsByAddr := make(map[string]string)
	pods := s.kubeController.ListAllPods()
	for _, pod := range pods {
		allPodsByAddr[pod.Status.PodIP] = fmt.Sprintf(`%s/%s`, pod.Namespace, pod.Name)
	}
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
								if pod, exists := allPodsByAddr[addrStr]; exists {
									if detachErr := tc.DetachBPFProg(maps.SysMesh, iface.Name, true, true); detachErr != nil {
										return fmt.Errorf(`%s %s`, pod, detachErr.Error())
									}
									delete(allPodsByAddr, addrStr)
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
	return allPodsByAddr
}
