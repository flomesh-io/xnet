package controller

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
	"github.com/flomesh-io/xnet/pkg/xnet/e4lb"
	"github.com/flomesh-io/xnet/pkg/xnet/ns"
	"github.com/flomesh-io/xnet/pkg/xnet/tc"
	"github.com/flomesh-io/xnet/pkg/xnet/volume"
)

func (s *server) checkAndRepairPods() {
	for {
		repairFailPods := s.doCheckAndRepairPods()
		if len(repairFailPods) == 0 {
			time.Sleep(time.Second * 10)
			continue
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

	log.Debug().Msgf("monitoredPodsByAddr Count: %d", len(monitoredPodsByAddr))
	log.Debug().Msgf("allPodsByAddr Count: %d", len(allPodsByAddr))

	for _, netnsDir := range volume.Netns {
		if len(monitoredPodsByAddr) == 0 {
			break
		}
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
				if iface, ifaceErr := net.InterfaceByName(podEth0); ifaceErr == nil {
					if (iface.Flags&net.FlagLoopback) == 0 && (iface.Flags&net.FlagUp) != 0 {
						if addrs, addrErr := iface.Addrs(); addrErr == nil {
							for _, addr := range addrs {
								addrStr := addr.String()
								addrStr = addrStr[0:strings.Index(addrStr, `/`)]
								log.Debug().Msgf("netns Addr:%s %s", iface.Name, addrStr)
								if pod, exists := monitoredPodsByAddr[addrStr]; exists {
									log.Debug().Msgf("monitoredPodsByAddr:%s", addrStr)
									if attachErr := tc.AttachBPFProg(maps.SysMesh, iface.Name, true, true); attachErr != nil {
										return fmt.Errorf(`%s %s`, pod, attachErr.Error())
									}
									log.Debug().Msgf("monitoredPodsByAddr:%s attach success", addrStr)
									delete(monitoredPodsByAddr, addrStr)
									delete(allPodsByAddr, addrStr)
								} else if pod, exists := allPodsByAddr[addrStr]; exists {
									log.Debug().Msgf("allPodsByAddr:%s", addrStr)
									if detachErr := tc.DetachBPFProg(maps.SysMesh, iface.Name, true, true); detachErr != nil {
										return fmt.Errorf(`%s %s`, pod, detachErr.Error())
									}
									log.Debug().Msgf("allPodsByAddr:%s detach success", addrStr)
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
	log.Debug().Msgf("monitoredPodsByAddr Attach Fail Count: %d", len(monitoredPodsByAddr))
	return monitoredPodsByAddr
}

func (s *server) checkAndResetPods() {
	retries := 3
	for {
		_ = s.doCheckAndResetPods()
		retries--
		if retries < 0 {
			break
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
	log.Debug().Msgf("allPodsByAddr Count: %d", len(allPodsByAddr))

	for _, netnsDir := range volume.Netns {
		if len(allPodsByAddr) == 0 {
			break
		}
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
				if iface, ifaceErr := net.InterfaceByName(podEth0); ifaceErr == nil {
					if (iface.Flags&net.FlagLoopback) == 0 && (iface.Flags&net.FlagUp) != 0 {
						if addrs, addrErr := iface.Addrs(); addrErr == nil {
							for _, addr := range addrs {
								addrStr := addr.String()
								addrStr = addrStr[0:strings.Index(addrStr, `/`)]
								log.Debug().Msgf("netns Addr:%s %s", iface.Name, addrStr)
								if pod, exists := allPodsByAddr[addrStr]; exists {
									if detachErr := tc.DetachBPFProg(maps.SysMesh, iface.Name, true, true); detachErr != nil {
										return fmt.Errorf(`%s %s`, pod, detachErr.Error())
									}
									log.Debug().Msgf("allPodsByAddr:%s detach success", addrStr)
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

func (s *server) checkAndRepairE4lb() {
	for {
		if !s.uninstallProg {
			if s.enableE4lb {
				if e4lb.E4lbOn() {
					break
				}
			}
		}
		time.Sleep(time.Second * 5)
	}
}
