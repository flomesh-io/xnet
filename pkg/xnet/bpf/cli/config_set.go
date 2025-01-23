package cli

import (
	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
)

const configSetDescription = ``
const configSetExample = ``

type configSetCmd struct {
	sys

	ipv6ProtoDenyAll             int8
	ipv4TCPProtoDenyAll          int8
	ipv4TCPProtoAllowAll         int8
	ipv4TCPProtoAllowNatEscape   int8
	ipv4UDPProtoDenyAll          int8
	ipv4UDPProtoAllowAll         int8
	ipv4UDPProtoAllowNatEscape   int8
	ipv4OTHProtoDenyAll          int8
	ipv4TCPNatByIpPortOn         int8
	ipv4TCPNatByIpOn             int8
	ipv4TCPNatAllOff             int8
	ipv4TCPNatOptOn              int8
	ipv4TCPNatOptWithLocalAddrOn int8
	ipv4TCPNatOptWithLocalPortOn int8
	ipv4UDPNatByIpPortOn         int8
	ipv4UDPNatByIpOn             int8
	ipv4UDPNatByPortOn           int8
	ipv4UDPNatAllOff             int8
	ipv4UDPNatOptOn              int8
	ipv4UDPNatOptWithLocalAddrOn int8
	ipv4UDPNatOptWithLocalPortOn int8
	ipv4AclCheckOn               int8
	ipv4TraceHdrOn               int8
	ipv4TraceNatOn               int8
	ipv4TraceOptOn               int8
	ipv4TraceAclOn               int8
	ipv4TraceFlowOn              int8
	ipv4TraceByIpOn              int8
	ipv4TraceByPortOn            int8

	debugOn bool
	optOn   bool
	aclOn   bool
}

func newConfigSet() *cobra.Command {
	configSet := &configSetCmd{}

	cmd := &cobra.Command{
		Use:   "set",
		Short: "set global configurations",
		Long:  configSetDescription,
		Args:  cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return configSet.run()
		},
		Example: configSetExample,
	}

	//add flags
	f := cmd.Flags()
	configSet.sys.addFlags(f)
	f.Int8Var(&configSet.ipv6ProtoDenyAll, "ipv6_proto_deny_all", -1, "--ipv6_proto_deny_all=0/1")
	f.Int8Var(&configSet.ipv4TCPProtoDenyAll, "ipv4_tcp_proto_deny_all", -1, "--ipv4_tcp_proto_deny_all=0/1")
	f.Int8Var(&configSet.ipv4TCPProtoAllowAll, "ipv4_tcp_proto_allow_all", -1, "--ipv4_tcp_proto_allow_all=0/1")
	f.Int8Var(&configSet.ipv4TCPProtoAllowNatEscape, "ipv4_tcp_proto_allow_nat_escape", -1, "--ipv4_tcp_proto_allow_nat_escape=0/1")
	f.Int8Var(&configSet.ipv4UDPProtoDenyAll, "ipv4_udp_proto_deny_all", -1, "--ipv4_udp_proto_deny_all=0/1")
	f.Int8Var(&configSet.ipv4UDPProtoAllowAll, "ipv4_udp_proto_allow_all", -1, "--ipv4_udp_proto_allow_all=0/1")
	f.Int8Var(&configSet.ipv4UDPProtoAllowNatEscape, "ipv4_udp_proto_allow_nat_escape", -1, "--ipv4_udp_proto_allow_nat_escape=0/1")
	f.Int8Var(&configSet.ipv4OTHProtoDenyAll, "ipv4_oth_proto_deny_all", -1, "--ipv4_oth_proto_deny_all=0/1")
	f.Int8Var(&configSet.ipv4TCPNatByIpPortOn, "ipv4_tcp_nat_by_ip_port_on", -1, "--ipv4_tcp_nat_by_ip_port_on=0/1")
	f.Int8Var(&configSet.ipv4TCPNatByIpOn, "ipv4_tcp_nat_by_ip_on", -1, "--ipv4_tcp_nat_by_ip_on=0/1")
	f.Int8Var(&configSet.ipv4TCPNatAllOff, "ipv4_tcp_nat_all_off", -1, "--ipv4_tcp_nat_all_off=0/1")
	f.Int8Var(&configSet.ipv4TCPNatOptOn, "ipv4_tcp_nat_opt_on", -1, "--ipv4_tcp_nat_opt_on=0/1")
	f.Int8Var(&configSet.ipv4TCPNatOptWithLocalAddrOn, "ipv4_tcp_nat_opt_with_local_addr_on", -1, "--ipv4_tcp_nat_opt_with_local_addr_on=0/1")
	f.Int8Var(&configSet.ipv4TCPNatOptWithLocalPortOn, "ipv4_tcp_nat_opt_with_local_port_on", -1, "--ipv4_tcp_nat_opt_with_local_port_on=0/1")
	f.Int8Var(&configSet.ipv4UDPNatByIpPortOn, "ipv4_udp_nat_by_ip_port_on", -1, "--ipv4_udp_nat_by_ip_port_on=0/1")
	f.Int8Var(&configSet.ipv4UDPNatByIpOn, "ipv4_udp_nat_by_ip_on", -1, "--ipv4_udp_nat_by_ip_on=0/1")
	f.Int8Var(&configSet.ipv4UDPNatByPortOn, "ipv4_udp_nat_by_port_on", -1, "--ipv4_udp_nat_by_port_on=0/1")
	f.Int8Var(&configSet.ipv4UDPNatAllOff, "ipv4_udp_nat_all_off", -1, "--ipv4_udp_nat_all_off=0/1")
	f.Int8Var(&configSet.ipv4UDPNatOptOn, "ipv4_udp_nat_opt_on", -1, "--ipv4_udp_nat_opt_on=0/1")
	f.Int8Var(&configSet.ipv4UDPNatOptWithLocalAddrOn, "ipv4_udp_nat_opt_with_local_addr_on", -1, "--ipv4_udp_nat_opt_with_local_addr_on=0/1")
	f.Int8Var(&configSet.ipv4UDPNatOptWithLocalPortOn, "ipv4_udp_nat_opt_with_local_port_on", -1, "--ipv4_udp_nat_opt_with_local_port_on=0/1")
	f.Int8Var(&configSet.ipv4AclCheckOn, "ipv4_acl_check_on", -1, "--ipv4_acl_check_on=0/1")
	f.Int8Var(&configSet.ipv4TraceHdrOn, "ipv4_trace_hdr_on", -1, "--ipv4_trace_hdr_on=0/1")
	f.Int8Var(&configSet.ipv4TraceNatOn, "ipv4_trace_nat_on", -1, "--ipv4_trace_nat_on=0/1")
	f.Int8Var(&configSet.ipv4TraceOptOn, "ipv4_trace_opt_on", -1, "--ipv4_trace_opt_on=0/1")
	f.Int8Var(&configSet.ipv4TraceAclOn, "ipv4_trace_acl_on", -1, "--ipv4_trace_acl_on=0/1")
	f.Int8Var(&configSet.ipv4TraceFlowOn, "ipv4_trace_flow_on", -1, "--ipv4_trace_flow_on=0/1")
	f.Int8Var(&configSet.ipv4TraceByIpOn, "ipv4_trace_by_ip_on", -1, "--ipv4_trace_by_ip_on=0/1")
	f.Int8Var(&configSet.ipv4TraceByPortOn, "ipv4_trace_by_port_on", -1, "--ipv4_trace_by_port_on=0/1")

	f.BoolVar(&configSet.debugOn, "debug-on", false, "--debug-on")
	f.BoolVar(&configSet.optOn, "opt-on", false, "--opt-on")
	f.BoolVar(&configSet.aclOn, "acl-on", false, "--acl-on")
	return cmd
}

func (a *configSetCmd) run() error {
	cfgVal, err := maps.GetXNetCfg(a.sysId())
	if err != nil {
		return err
	}
	if cfgVal != nil {
		if a.debugOn {
			a.setDebugOn()
		}
		if a.optOn {
			a.setOptOn()
		}
		if a.aclOn {
			a.setAclOn()
		}
		a.setIPv6(cfgVal)
		a.setProto(cfgVal)
		a.setNat(cfgVal)
		a.setNatOpt(cfgVal)
		a.setAcl(cfgVal)
		a.setTracer(cfgVal)
		return maps.SetXNetCfg(a.sysId(), cfgVal)
	}
	return nil
}

func (a *configSetCmd) setDebugOn() {
	a.ipv4TraceHdrOn = 1
	a.ipv4TraceNatOn = 1
	a.ipv4TraceOptOn = 1
	a.ipv4TraceAclOn = 1
	a.ipv4TraceFlowOn = 1
	a.ipv4TraceByIpOn = 1
	a.ipv4TraceByPortOn = 1
}

func (a *configSetCmd) setOptOn() {
	a.ipv4TCPNatOptOn = 1
	a.ipv4TCPNatOptWithLocalAddrOn = 1
	a.ipv4TCPNatOptWithLocalPortOn = 1
	a.ipv4UDPNatOptOn = 1
	a.ipv4UDPNatOptWithLocalAddrOn = 1
	a.ipv4UDPNatOptWithLocalPortOn = 1
}

func (a *configSetCmd) setAclOn() {
	a.ipv4AclCheckOn = 1
}

func (a *configSetCmd) setAcl(cfgVal *maps.CfgVal) {
	if a.ipv4AclCheckOn == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4AclCheckOn)
	} else if a.ipv4AclCheckOn == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4AclCheckOn)
	}
}

func (a *configSetCmd) setNat(cfgVal *maps.CfgVal) {
	if a.ipv4TCPNatByIpPortOn == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4TCPNatByIpPortOn)
	} else if a.ipv4TCPNatByIpPortOn == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4TCPNatByIpPortOn)
	}

	if a.ipv4TCPNatByIpOn == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4TCPNatByIpOn)
	} else if a.ipv4TCPNatByIpOn == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4TCPNatByIpOn)
	}

	if a.ipv4TCPNatAllOff == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4TCPNatAllOff)
	} else if a.ipv4TCPNatAllOff == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4TCPNatAllOff)
	}

	if a.ipv4UDPNatByIpPortOn == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4UDPNatByIpPortOn)
	} else if a.ipv4UDPNatByIpPortOn == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4UDPNatByIpPortOn)
	}

	if a.ipv4UDPNatByIpOn == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4UDPNatByIpOn)
	} else if a.ipv4UDPNatByIpOn == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4UDPNatByIpOn)
	}

	if a.ipv4UDPNatByPortOn == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4UDPNatByPortOn)
	} else if a.ipv4UDPNatByPortOn == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4UDPNatByPortOn)
	}

	if a.ipv4UDPNatAllOff == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4UDPNatAllOff)
	} else if a.ipv4UDPNatAllOff == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4UDPNatAllOff)
	}
}

func (a *configSetCmd) setNatOpt(cfgVal *maps.CfgVal) {
	if a.ipv4TCPNatOptOn == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4TCPNatOptOn)
	} else if a.ipv4TCPNatOptOn == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4TCPNatOptOn)
	}

	if a.ipv4TCPNatOptWithLocalAddrOn == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4TCPNatOptWithLocalAddrOn)
	} else if a.ipv4TCPNatOptWithLocalAddrOn == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4TCPNatOptWithLocalAddrOn)
	}

	if a.ipv4TCPNatOptWithLocalPortOn == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4TCPNatOptWithLocalPortOn)
	} else if a.ipv4TCPNatOptWithLocalPortOn == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4TCPNatOptWithLocalPortOn)
	}

	if a.ipv4UDPNatOptOn == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4UDPNatOptOn)
	} else if a.ipv4UDPNatOptOn == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4UDPNatOptOn)
	}

	if a.ipv4UDPNatOptWithLocalAddrOn == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4UDPNatOptWithLocalAddrOn)
	} else if a.ipv4UDPNatOptWithLocalAddrOn == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4UDPNatOptWithLocalAddrOn)
	}

	if a.ipv4UDPNatOptWithLocalPortOn == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4UDPNatOptWithLocalPortOn)
	} else if a.ipv4UDPNatOptWithLocalPortOn == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4UDPNatOptWithLocalPortOn)
	}
}

func (a *configSetCmd) setProto(cfgVal *maps.CfgVal) {
	if a.ipv4TCPProtoDenyAll == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4TCPProtoDenyAll)
	} else if a.ipv4TCPProtoDenyAll == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4TCPProtoDenyAll)
	}

	if a.ipv4TCPProtoAllowAll == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4TCPProtoAllowAll)
	} else if a.ipv4TCPProtoAllowAll == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4TCPProtoAllowAll)
	}

	if a.ipv4TCPProtoAllowNatEscape == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4TCPProtoAllowNatEscape)
	} else if a.ipv4TCPProtoAllowNatEscape == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4TCPProtoAllowNatEscape)
	}

	if a.ipv4UDPProtoDenyAll == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4UDPProtoDenyAll)
	} else if a.ipv4UDPProtoDenyAll == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4UDPProtoDenyAll)
	}

	if a.ipv4UDPProtoAllowAll == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4UDPProtoAllowAll)
	} else if a.ipv4UDPProtoAllowAll == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4UDPProtoAllowAll)
	}

	if a.ipv4UDPProtoAllowNatEscape == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4UDPProtoAllowNatEscape)
	} else if a.ipv4UDPProtoAllowNatEscape == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4UDPProtoAllowNatEscape)
	}

	if a.ipv4OTHProtoDenyAll == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4OTHProtoDenyAll)
	} else if a.ipv4OTHProtoDenyAll == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4OTHProtoDenyAll)
	}
}

func (a *configSetCmd) setIPv6(cfgVal *maps.CfgVal) {
	if a.ipv6ProtoDenyAll == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv6ProtoDenyAll)
	} else if a.ipv6ProtoDenyAll == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv6ProtoDenyAll)
	}
}

func (a *configSetCmd) setTracer(cfgVal *maps.CfgVal) {
	if a.ipv4TraceHdrOn == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4TraceHdrOn)
	} else if a.ipv4TraceHdrOn == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4TraceHdrOn)
	}

	if a.ipv4TraceNatOn == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4TraceNatOn)
	} else if a.ipv4TraceNatOn == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4TraceNatOn)
	}

	if a.ipv4TraceOptOn == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4TraceOptOn)
	} else if a.ipv4TraceOptOn == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4TraceOptOn)
	}

	if a.ipv4TraceAclOn == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4TraceAclOn)
	} else if a.ipv4TraceAclOn == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4TraceAclOn)
	}

	if a.ipv4TraceFlowOn == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4TraceFlowOn)
	} else if a.ipv4TraceFlowOn == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4TraceFlowOn)
	}

	if a.ipv4TraceByIpOn == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4TraceByIpOn)
	} else if a.ipv4TraceByIpOn == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4TraceByIpOn)
	}

	if a.ipv4TraceByPortOn == 1 {
		cfgVal.Set(maps.CfgFlagOffsetIPv4TraceByPortOn)
	} else if a.ipv4TraceByPortOn == 0 {
		cfgVal.Clear(maps.CfgFlagOffsetIPv4TraceByPortOn)
	}
}
