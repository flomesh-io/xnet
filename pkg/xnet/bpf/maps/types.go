package maps

import (
	"github.com/flomesh-io/xnet/pkg/logger"
)

var (
	log = logger.New("fsm-xnet-ebpf-maps")
)

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
	CfgFlagOffsetIPv6ProtoDenyAll uint8 = iota
	CfgFlagOffsetIPv4TCPProtoDenyAll
	CfgFlagOffsetIPv4TCPProtoAllowAll
	CfgFlagOffsetIPv4TCPProtoAllowNatEscape
	CfgFlagOffsetIPv4UDPProtoDenyAll
	CfgFlagOffsetIPv4UDPProtoAllowAll
	CfgFlagOffsetIPv4UDPProtoAllowNatEscape
	CfgFlagOffsetIPv4OTHProtoDenyAll
	CfgFlagOffsetIPv4TCPNatByIpPortOn
	CfgFlagOffsetIPv4TCPNatByIpOn
	CfgFlagOffsetIPv4TCPNatAllOff
	CfgFlagOffsetIPv4TCPNatOptOn
	CfgFlagOffsetIPv4TCPNatOptWithLocalAddrOn
	CfgFlagOffsetIPv4TCPNatOptWithLocalPortOn
	CfgFlagOffsetIPv4UDPNatByIpPortOn
	CfgFlagOffsetIPv4UDPNatByIpOn
	CfgFlagOffsetIPv4UDPNatByPortOn
	CfgFlagOffsetIPv4UDPNatAllOff
	CfgFlagOffsetIPv4UDPNatOptOn
	CfgFlagOffsetIPv4UDPNatOptWithLocalAddrOn
	CfgFlagOffsetIPv4UDPNatOptWithLocalPortOn
	CfgFlagOffsetIPv4AclCheckOn
	CfgFlagOffsetIPv4TraceHdrOn
	CfgFlagOffsetIPv4TraceNatOn
	CfgFlagOffsetIPv4TraceOptOn
	CfgFlagOffsetIPv4TraceAclOn
	CfgFlagOffsetIPv4TraceFlowOn
	CfgFlagOffsetIPv4TraceByIpOn
	CfgFlagOffsetIPv4TraceByPortOn
	CfgFlagMax
)

var flagNames = [CfgFlagMax]string{
	"ipv6_proto_deny_all",
	"ipv4_tcp_proto_deny_all",
	"ipv4_tcp_proto_allow_all",
	"ipv4_tcp_proto_allow_nat_escape",
	"ipv4_udp_proto_deny_all",
	"ipv4_udp_proto_allow_all",
	"ipv4_udp_proto_allow_nat_escape",
	"ipv4_oth_proto_deny_all",
	"ipv4_tcp_nat_by_ip_port_on",
	"ipv4_tcp_nat_by_ip_on",
	"ipv4_tcp_nat_all_off",
	"ipv4_tcp_nat_opt_on",
	"ipv4_tcp_nat_opt_with_local_addr_on",
	"ipv4_tcp_nat_opt_with_local_port_on",
	"ipv4_udp_nat_by_ip_port_on",
	"ipv4_udp_nat_by_ip_on",
	"ipv4_udp_nat_by_port_on",
	"ipv4_udp_nat_all_off",
	"ipv4_udp_nat_opt_on",
	"ipv4_udp_nat_opt_with_local_addr_on",
	"ipv4_udp_nat_opt_with_local_port_on",
	"ipv4_acl_check_on",
	"ipv4_trace_hdr_on",
	"ipv4_trace_nat_on",
	"ipv4_trace_opt_on",
	"ipv4_trace_acl_on",
	"ipv4_trace_flow_on",
	"ipv4_trace_by_ip_on",
	"ipv4_trace_by_port_on",
}
