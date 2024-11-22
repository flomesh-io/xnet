package tc

import (
	"fmt"
	"net"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"

	"github.com/flomesh-io/xnet/pkg/logger"
	"github.com/flomesh-io/xnet/pkg/xnet/bpf"
	"github.com/flomesh-io/xnet/pkg/xnet/bpf/fs"
)

var (
	log = logger.New("fsm-xnet-tc")
)

func uint32Ptr(v uint32) *uint32 {
	return &v
}

func stringPtr(v string) *string {
	return &v
}

func getBPFObjFD(objName string) (int, error) {
	pinnedFile := fs.GetPinningFile(objName)
	if pinnedProg, progErr := ebpf.LoadPinnedProgram(pinnedFile, &ebpf.LoadPinOptions{}); progErr == nil {
		return pinnedProg.FD(), nil
	} else {
		return -1, progErr
	}
}

func GetBPFQdisc(rtnl *tc.Tc, ifIndex uint32) (*tc.Object, error) {
	qdiscs, qdiscErr := rtnl.Qdisc().Get()
	if qdiscErr != nil {
		log.Error().Msgf("get qdisc error: %v", qdiscErr)
		return nil, qdiscErr
	}

	for _, qdisc := range qdiscs {
		if qdisc.Kind == TC_KIND_CLSACT && qdisc.Ifindex == ifIndex {
			bpfQdisc := qdisc
			return &bpfQdisc, nil
		}
	}
	return nil, nil
}

func addBPFQdisc(rtnl *tc.Tc, ifIndex uint32) error {
	return rtnl.Qdisc().Add(&tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: ifIndex,
			Handle:  core.BuildHandle(0xFFFF, 0x0000),
			Parent:  tc.HandleIngress,
		},
		Attribute: tc.Attribute{
			Kind: TC_KIND_CLSACT,
		},
	})
}

func GetBPFFilter(rtnl *tc.Tc, ifIndex, parent uint32) (*tc.Object, error) {
	msg := tc.Msg{
		Family:  unix.AF_UNSPEC,
		Ifindex: ifIndex,
		Handle:  0,
		Parent:  parent,
		Info:    0,
	}

	filters, err := rtnl.Filter().Get(&msg)
	if err != nil {
		return nil, err
	}

	for _, filter := range filters {
		if TC_KIND_BPF == filter.Kind && filter.BPF != nil && strings.HasPrefix(*filter.BPF.Name, TC_BPF_FILTER_PREFIX) {
			bpfFilter := filter
			return &bpfFilter, nil
		}
	}

	return nil, nil
}

func addBPFFilter(rtnl *tc.Tc, ifIndex, parent, progFD uint32) error {
	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: ifIndex,
			// Handle:  0,
			Parent: parent, // ingress
			Info: core.BuildHandle(
				66,     // prio
				0x0300, // protocol
			),
		},
		Attribute: tc.Attribute{
			Kind: TC_KIND_BPF,
			BPF: &tc.Bpf{
				FD:    uint32Ptr(progFD),
				Name:  stringPtr(fmt.Sprintf("%s_%d", TC_BPF_FILTER_PREFIX, progFD)),
				Flags: uint32Ptr(0x1),
			},
		},
	}
	return rtnl.Filter().Add(&filter)
}

func deleteBPFFilter(rtnl *tc.Tc, ifIndex, parent, progFD uint32) error {
	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: ifIndex,
			// Handle:  0,
			Parent: parent, // ingress
			Info: core.BuildHandle(
				66,     // prio
				0x0300, // protocol
			),
		},
		Attribute: tc.Attribute{
			Kind: TC_KIND_BPF,
			BPF: &tc.Bpf{
				FD:    uint32Ptr(progFD),
				Name:  stringPtr(fmt.Sprintf("%s_%d", TC_BPF_FILTER_PREFIX, progFD)),
				Flags: uint32Ptr(0x1),
			},
		},
	}
	return rtnl.Filter().Delete(&filter)
}

func ShowBPFProg(dev string) error {
	iface, ifaceErr := net.InterfaceByName(dev)
	if ifaceErr != nil {
		return ifaceErr
	}

	rtnl, rtnlErr := tc.Open(&tc.Config{})
	if rtnlErr != nil {
		return rtnlErr
	}

	defer func() {
		if err := rtnl.Close(); err != nil {
			log.Error().Msgf("could not close rtnetlink socket: %v\n", err)
		}
	}()

	if qdisc, _ := GetBPFQdisc(rtnl, uint32(iface.Index)); qdisc == nil {
		return nil
	}

	hasIngressFilter := false

	fmt.Print(`{`)
	if filter, _ := GetBPFFilter(rtnl, uint32(iface.Index), HandleIngress); filter != nil {
		hasIngressFilter = true
		fmt.Printf(`"ingress":"%s"`, *filter.Attribute.BPF.Name)
	}

	if filter, _ := GetBPFFilter(rtnl, uint32(iface.Index), HandleEgress); filter != nil {
		if hasIngressFilter {
			fmt.Print(`,`)
		}
		fmt.Printf(`"egress":"%s"`, *filter.Attribute.BPF.Name)
	}
	fmt.Println(`}`)

	return nil
}

func AttachBPFProg(dev string) error {
	iface, ifaceErr := net.InterfaceByName(dev)
	if ifaceErr != nil {
		log.Error().Msgf("get iface error: %v", ifaceErr)
		return ifaceErr
	}

	rtnl, rtnlErr := tc.Open(&tc.Config{})
	if rtnlErr != nil {
		log.Error().Msgf("open rtnl error: %v", rtnlErr)
		return rtnlErr
	}

	defer func() {
		if err := rtnl.Close(); err != nil {
			log.Error().Msgf("could not close rtnetlink socket: %v\n", err)
		}
	}()

	ingressProgFD, ingressProgFDErr := getBPFObjFD(bpf.FSM_CNI_INGRESS_PROG_NAME)
	if ingressProgFDErr != nil {
		log.Error().Msgf("fail to load sidecar ingress prog: %v", ingressProgFDErr)
		return ingressProgFDErr
	}

	egressProgFD, egressProgFDErr := getBPFObjFD(bpf.FSM_CNI_EGRESS_PROG_NAME)
	if egressProgFDErr != nil {
		log.Error().Msgf("fail to load sidecar egress prog: %v", egressProgFDErr)
		return egressProgFDErr
	}

	if qdisc, qdiscErr := GetBPFQdisc(rtnl, uint32(iface.Index)); qdiscErr != nil {
		log.Error().Msgf("get qdisc error: %v", qdiscErr)
		return qdiscErr
	} else if qdisc == nil {
		if err := addBPFQdisc(rtnl, uint32(iface.Index)); err != nil {
			return err
		}
	}

	if filter, _ := GetBPFFilter(rtnl, uint32(iface.Index), HandleIngress); filter == nil {
		if err := addBPFFilter(rtnl, uint32(iface.Index), HandleIngress, uint32(ingressProgFD)); err != nil {
			return err
		}
	}

	if filter, _ := GetBPFFilter(rtnl, uint32(iface.Index), HandleEgress); filter == nil {
		if err := addBPFFilter(rtnl, uint32(iface.Index), HandleEgress, uint32(egressProgFD)); err != nil {
			return err
		}
	}

	return nil
}

func DetachBPFProg(dev string) error {
	iface, ifaceErr := net.InterfaceByName(dev)
	if ifaceErr != nil {
		return ifaceErr
	}

	rtnl, rtnlErr := tc.Open(&tc.Config{})
	if rtnlErr != nil {
		return rtnlErr
	}

	defer func() {
		if err := rtnl.Close(); err != nil {
			log.Error().Msgf("could not close rtnetlink socket: %v\n", err)
		}
	}()

	if qdisc, _ := GetBPFQdisc(rtnl, uint32(iface.Index)); qdisc == nil {
		return nil
	}

	if filter, _ := GetBPFFilter(rtnl, uint32(iface.Index), HandleIngress); filter != nil {
		ingressProgFD, ingressProgFDErr := getBPFObjFD(bpf.FSM_CNI_INGRESS_PROG_NAME)
		if ingressProgFDErr == nil {
			if err := deleteBPFFilter(rtnl, uint32(iface.Index), HandleIngress, uint32(ingressProgFD)); err != nil {
				log.Error().Msg(err.Error())
			}
		}
	}

	if filter, _ := GetBPFFilter(rtnl, uint32(iface.Index), HandleEgress); filter != nil {
		egressProgFD, egressProgFDErr := getBPFObjFD(bpf.FSM_CNI_EGRESS_PROG_NAME)
		if egressProgFDErr == nil {
			if err := deleteBPFFilter(rtnl, uint32(iface.Index), HandleEgress, uint32(egressProgFD)); err != nil {
				log.Error().Msg(err.Error())
			}
		}
	}

	return nil
}
