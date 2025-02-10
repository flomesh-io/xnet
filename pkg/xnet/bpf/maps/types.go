package maps

import (
	"github.com/flomesh-io/xnet/pkg/logger"
)

var (
	log = logger.New("fsm-xnet-ebpf-maps")
)

const (
	SysNoop = SysID(0)
	SysMesh = SysID(1)
	SysE4lb = SysID(2)
)

type SysID uint32

type ProgKey uint32
type ProgVal int

type NatKey FsmNatKeyT
type NatVal FsmNatOpT

type AclKey FsmAclKeyT
type AclVal FsmAclOpT

type FlowKey FsmFlowT
type FlowTCPVal FsmFlowTOpT
type FlowUDPVal FsmFlowUOpT

type OptKey FsmOptKeyT
type OptVal FsmFlowT

type CfgKey uint32
type CfgVal FsmCfgT

type IFaceKey FsmIfNameT
type IFaceVal FsmIfInfoT

type TraceIPKey FsmTrIpT
type TraceIPVal FsmTrOpT

type TracePortKey FsmTrPortT
type TracePortVal FsmTrOpT

type FlagT struct {
	Flags uint64
}

type UpStream struct {
	Addr string
	Port uint16
}

const (
	IPPROTO_TCP L4Proto = 6
	IPPROTO_UDP L4Proto = 17
)

type L4Proto uint8

const (
	TC_DIR_IGR TcDir = 0
	TC_DIR_EGR TcDir = 1
)

type TcDir uint8

const (
	ACL_DENY    Acl = 0
	ACL_AUDIT   Acl = 1
	ACL_TRUSTED Acl = 2
)

type Acl uint8

const (
	NF_DENY    = 0
	NF_ALLOW   = 1
	NF_XNAT    = 2
	NF_RDIR    = 4
	NF_SKIP_SM = 8
)

const (
	CfgFlagOffsetDenyAll uint8 = iota
	CfgFlagOffsetAllowAll
	CfgFlagOffsetTCPProtoDenyAll
	CfgFlagOffsetTCPProtoAllowAll
	CfgFlagOffsetTCPProtoAllowNatEscape
	CfgFlagOffsetUDPProtoDenyAll
	CfgFlagOffsetUDPProtoAllowAll
	CfgFlagOffsetUDPProtoAllowNatEscape
	CfgFlagOffsetOTHProtoDenyAll
	CfgFlagOffsetTCPNatByIpPortOn
	CfgFlagOffsetTCPNatByIpOn
	CfgFlagOffsetTCPNatAllOff
	CfgFlagOffsetTCPNatOptOn
	CfgFlagOffsetTCPNatOptWithLocalAddrOn
	CfgFlagOffsetTCPNatOptWithLocalPortOn
	CfgFlagOffsetUDPNatByIpPortOn
	CfgFlagOffsetUDPNatByIpOn
	CfgFlagOffsetUDPNatByPortOn
	CfgFlagOffsetUDPNatAllOff
	CfgFlagOffsetUDPNatOptOn
	CfgFlagOffsetUDPNatOptWithLocalAddrOn
	CfgFlagOffsetUDPNatOptWithLocalPortOn
	CfgFlagOffsetAclCheckOn
	CfgFlagOffsetTraceHdrOn
	CfgFlagOffsetTraceNatOn
	CfgFlagOffsetTraceOptOn
	CfgFlagOffsetTraceAclOn
	CfgFlagOffsetTraceFlowOn
	CfgFlagOffsetTraceByIpOn
	CfgFlagOffsetTraceByPortOn
	CfgFlagMax
)

var flagNames = [CfgFlagMax]string{
	"deny_all",
	"allow_all",
	"tcp_proto_deny_all",
	"tcp_proto_allow_all",
	"tcp_proto_allow_nat_escape",
	"udp_proto_deny_all",
	"udp_proto_allow_all",
	"udp_proto_allow_nat_escape",
	"oth_proto_deny_all",
	"tcp_nat_by_ip_port_on",
	"tcp_nat_by_ip_on",
	"tcp_nat_all_off",
	"tcp_nat_opt_on",
	"tcp_nat_opt_with_local_addr_on",
	"tcp_nat_opt_with_local_port_on",
	"udp_nat_by_ip_port_on",
	"udp_nat_by_ip_on",
	"udp_nat_by_port_on",
	"udp_nat_all_off",
	"udp_nat_opt_on",
	"udp_nat_opt_with_local_addr_on",
	"udp_nat_opt_with_local_port_on",
	"acl_check_on",
	"trace_hdr_on",
	"trace_nat_on",
	"trace_opt_on",
	"trace_acl_on",
	"trace_flow_on",
	"trace_by_ip_on",
	"trace_by_port_on",
}
