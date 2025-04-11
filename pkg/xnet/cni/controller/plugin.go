package controller

import (
	"fmt"
	"net"
	"runtime/debug"
	"strings"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
	"github.com/flomesh-io/xnet/pkg/xnet/cni/plugin"
	"github.com/flomesh-io/xnet/pkg/xnet/ns"
	"github.com/flomesh-io/xnet/pkg/xnet/tc"
	"github.com/flomesh-io/xnet/pkg/xnet/volume"
)

func (s *server) CmdAdd(args *skel.CmdArgs) (err error) {
	defer func() {
		if e := recover(); e != nil {
			msg := fmt.Sprintf("xcni panic during cmdAdd: %v\n%v", e, string(debug.Stack()))
			if err != nil {
				// If we're recovering and there was also an error, then we need to
				// present both.
				msg = fmt.Sprintf("%s: %v", msg, err)
			}
			err = fmt.Errorf("%s", msg)
		}
		if err != nil {
			log.Error().Msgf("xcni cmdAdd error: %v", err)
		}
	}()

	k8sArgs := plugin.K8sArgs{}
	if err = types.LoadArgs(args.Args, &k8sArgs); err != nil {
		return err
	}

	namespace := string(k8sArgs.K8S_POD_NAME)
	pod := string(k8sArgs.K8S_POD_NAMESPACE)
	if monitoredPod := s.kubeController.IsMonitoredPod(namespace, pod); !monitoredPod {
		return nil
	}

	log.Debug().Msgf("CmdAdd %s/%s", pod, namespace)

	nsPath := strings.Replace(args.Netns, volume.SysRun.HostPath, volume.SysRun.MountPath, 1)
	nsPath = strings.Replace(nsPath, volume.SysProc.HostPath, volume.SysProc.MountPath, 1)
	netNS, err := ns.GetNS(nsPath)
	if err != nil {
		log.Error().Msgf("get ns %s error", args.Netns)
		return err
	}

	err = netNS.Do(func(_ ns.NetNS) error {
		// attach tc to the device
		if len(args.IfName) != 0 {
			return tc.AttachBPFProg(maps.SysMesh, args.IfName, true, true)
		}
		if iface, ifaceErr := net.InterfaceByName(podEth0); ifaceErr == nil {
			if (iface.Flags&net.FlagLoopback) == 0 && (iface.Flags&net.FlagUp) != 0 {
				return tc.AttachBPFProg(maps.SysMesh, iface.Name, true, true)
			}
		}
		return fmt.Errorf("device not found for %s", args.Netns)
	})
	if err != nil {
		log.Error().Msgf("CmdAdd failed for %s: %v", args.Netns, err)
	}
	return err
}

func (s *server) CmdDelete(args *skel.CmdArgs) error {
	//k8sArgs := cli.K8sArgs{}
	//if err := types.LoadArgs(args.Args, &k8sArgs); err != nil {
	//	return err
	//}

	//namespace := string(k8sArgs.K8S_POD_NAME)
	//pod := string(k8sArgs.K8S_POD_NAMESPACE)
	//log.Debug().Msgf("CmdDelete %s/%s", pod, namespace)
	return nil
}
