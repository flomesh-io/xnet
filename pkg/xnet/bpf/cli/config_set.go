package cli

import (
	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
)

const configSetDescription = ``
const configSetExample = ``

type configSetCmd struct {
	sys

	ipv4 bool
	ipv6 bool

	denyAll                  int8
	allowAll                 int8
	tcpProtoDenyAll          int8
	tcpProtoAllowAll         int8
	tcpProtoAllowNatEscape   int8
	udpProtoDenyAll          int8
	udpProtoAllowAll         int8
	udpProtoAllowNatEscape   int8
	othProtoDenyAll          int8
	tcpNatByIpPortOn         int8
	tcpNatByIpOn             int8
	tcpNatAllOff             int8
	tcpNatOptOn              int8
	tcpNatOptWithLocalAddrOn int8
	tcpNatOptWithLocalPortOn int8
	udpNatByIpPortOn         int8
	udpNatByIpOn             int8
	udpNatByPortOn           int8
	udpNatAllOff             int8
	udpNatOptOn              int8
	udpNatOptWithLocalAddrOn int8
	udpNatOptWithLocalPortOn int8
	aclCheckOn               int8
	traceHdrOn               int8
	traceNatOn               int8
	traceOptOn               int8
	traceAclOn               int8
	traceFlowOn              int8
	traceByIpOn              int8
	traceByPortOn            int8

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
	f.BoolVar(&configSet.ipv4, "ipv4", false, "--ipv4")
	f.BoolVar(&configSet.ipv6, "ipv6", false, "--ipv6")

	f.Int8Var(&configSet.denyAll, "deny_all", -1, "--deny_all=0/1")
	f.Int8Var(&configSet.allowAll, "allow_all", -1, "--allow_all=0/1")
	f.Int8Var(&configSet.tcpProtoDenyAll, "tcp_proto_deny_all", -1, "--tcp_proto_deny_all=0/1")
	f.Int8Var(&configSet.tcpProtoAllowAll, "tcp_proto_allow_all", -1, "--tcp_proto_allow_all=0/1")
	f.Int8Var(&configSet.tcpProtoAllowNatEscape, "tcp_proto_allow_nat_escape", -1, "--tcp_proto_allow_nat_escape=0/1")
	f.Int8Var(&configSet.udpProtoDenyAll, "udp_proto_deny_all", -1, "--udp_proto_deny_all=0/1")
	f.Int8Var(&configSet.udpProtoAllowAll, "udp_proto_allow_all", -1, "--udp_proto_allow_all=0/1")
	f.Int8Var(&configSet.udpProtoAllowNatEscape, "udp_proto_allow_nat_escape", -1, "--udp_proto_allow_nat_escape=0/1")
	f.Int8Var(&configSet.othProtoDenyAll, "oth_proto_deny_all", -1, "--oth_proto_deny_all=0/1")
	f.Int8Var(&configSet.tcpNatByIpPortOn, "tcp_nat_by_ip_port_on", -1, "--tcp_nat_by_ip_port_on=0/1")
	f.Int8Var(&configSet.tcpNatByIpOn, "tcp_nat_by_ip_on", -1, "--tcp_nat_by_ip_on=0/1")
	f.Int8Var(&configSet.tcpNatAllOff, "tcp_nat_all_off", -1, "--tcp_nat_all_off=0/1")
	f.Int8Var(&configSet.tcpNatOptOn, "tcp_nat_opt_on", -1, "--tcp_nat_opt_on=0/1")
	f.Int8Var(&configSet.tcpNatOptWithLocalAddrOn, "tcp_nat_opt_with_local_addr_on", -1, "--tcp_nat_opt_with_local_addr_on=0/1")
	f.Int8Var(&configSet.tcpNatOptWithLocalPortOn, "tcp_nat_opt_with_local_port_on", -1, "--tcp_nat_opt_with_local_port_on=0/1")
	f.Int8Var(&configSet.udpNatByIpPortOn, "udp_nat_by_ip_port_on", -1, "--udp_nat_by_ip_port_on=0/1")
	f.Int8Var(&configSet.udpNatByIpOn, "udp_nat_by_ip_on", -1, "--udp_nat_by_ip_on=0/1")
	f.Int8Var(&configSet.udpNatByPortOn, "udp_nat_by_port_on", -1, "--udp_nat_by_port_on=0/1")
	f.Int8Var(&configSet.udpNatAllOff, "udp_nat_all_off", -1, "--udp_nat_all_off=0/1")
	f.Int8Var(&configSet.udpNatOptOn, "udp_nat_opt_on", -1, "--udp_nat_opt_on=0/1")
	f.Int8Var(&configSet.udpNatOptWithLocalAddrOn, "udp_nat_opt_with_local_addr_on", -1, "--udp_nat_opt_with_local_addr_on=0/1")
	f.Int8Var(&configSet.udpNatOptWithLocalPortOn, "udp_nat_opt_with_local_port_on", -1, "--udp_nat_opt_with_local_port_on=0/1")
	f.Int8Var(&configSet.aclCheckOn, "acl_check_on", -1, "--acl_check_on=0/1")
	f.Int8Var(&configSet.traceHdrOn, "trace_hdr_on", -1, "--trace_hdr_on=0/1")
	f.Int8Var(&configSet.traceNatOn, "trace_nat_on", -1, "--trace_nat_on=0/1")
	f.Int8Var(&configSet.traceOptOn, "trace_opt_on", -1, "--trace_opt_on=0/1")
	f.Int8Var(&configSet.traceAclOn, "trace_acl_on", -1, "--trace_acl_on=0/1")
	f.Int8Var(&configSet.traceFlowOn, "trace_flow_on", -1, "--trace_flow_on=0/1")
	f.Int8Var(&configSet.traceByIpOn, "trace_by_ip_on", -1, "--trace_by_ip_on=0/1")
	f.Int8Var(&configSet.traceByPortOn, "trace_by_port_on", -1, "--trace_by_port_on=0/1")

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
		a.setDeny(cfgVal)
		a.setAllow(cfgVal)
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
	a.traceHdrOn = 1
	a.traceNatOn = 1
	a.traceOptOn = 1
	a.traceAclOn = 1
	a.traceFlowOn = 1
	a.traceByIpOn = 1
	a.traceByPortOn = 1
}

func (a *configSetCmd) setOptOn() {
	a.tcpNatOptOn = 1
	a.tcpNatOptWithLocalAddrOn = 1
	a.tcpNatOptWithLocalPortOn = 1
	a.udpNatOptOn = 1
	a.udpNatOptWithLocalAddrOn = 1
	a.udpNatOptWithLocalPortOn = 1
}

func (a *configSetCmd) setAclOn() {
	a.aclCheckOn = 1
}

func (a *configSetCmd) setAcl(cfgVal *maps.CfgVal) {
	var protos []*maps.FlagT
	if a.ipv4 {
		protos = append(protos, cfgVal.IPv4())
	}
	if a.ipv6 {
		protos = append(protos, cfgVal.IPv6())
	}
	if len(protos) == 0 {
		return
	}

	for _, proto := range protos {
		if a.aclCheckOn == 1 {
			proto.Set(maps.CfgFlagOffsetAclCheckOn)
		} else if a.aclCheckOn == 0 {
			proto.Clear(maps.CfgFlagOffsetAclCheckOn)
		}
	}
}

func (a *configSetCmd) setNat(cfgVal *maps.CfgVal) {
	var protos []*maps.FlagT
	if a.ipv4 {
		protos = append(protos, cfgVal.IPv4())
	}
	if a.ipv6 {
		protos = append(protos, cfgVal.IPv6())
	}
	if len(protos) == 0 {
		return
	}

	for _, proto := range protos {
		if a.tcpNatByIpPortOn == 1 {
			proto.Set(maps.CfgFlagOffsetTCPNatByIpPortOn)
		} else if a.tcpNatByIpPortOn == 0 {
			proto.Clear(maps.CfgFlagOffsetTCPNatByIpPortOn)
		}

		if a.tcpNatByIpOn == 1 {
			proto.Set(maps.CfgFlagOffsetTCPNatByIpOn)
		} else if a.tcpNatByIpOn == 0 {
			proto.Clear(maps.CfgFlagOffsetTCPNatByIpOn)
		}

		if a.tcpNatAllOff == 1 {
			proto.Set(maps.CfgFlagOffsetTCPNatAllOff)
		} else if a.tcpNatAllOff == 0 {
			proto.Clear(maps.CfgFlagOffsetTCPNatAllOff)
		}

		if a.udpNatByIpPortOn == 1 {
			proto.Set(maps.CfgFlagOffsetUDPNatByIpPortOn)
		} else if a.udpNatByIpPortOn == 0 {
			proto.Clear(maps.CfgFlagOffsetUDPNatByIpPortOn)
		}

		if a.udpNatByIpOn == 1 {
			proto.Set(maps.CfgFlagOffsetUDPNatByIpOn)
		} else if a.udpNatByIpOn == 0 {
			proto.Clear(maps.CfgFlagOffsetUDPNatByIpOn)
		}

		if a.udpNatByPortOn == 1 {
			proto.Set(maps.CfgFlagOffsetUDPNatByPortOn)
		} else if a.udpNatByPortOn == 0 {
			proto.Clear(maps.CfgFlagOffsetUDPNatByPortOn)
		}

		if a.udpNatAllOff == 1 {
			proto.Set(maps.CfgFlagOffsetUDPNatAllOff)
		} else if a.udpNatAllOff == 0 {
			proto.Clear(maps.CfgFlagOffsetUDPNatAllOff)
		}
	}
}

func (a *configSetCmd) setNatOpt(cfgVal *maps.CfgVal) {
	var protos []*maps.FlagT
	if a.ipv4 {
		protos = append(protos, cfgVal.IPv4())
	}
	if a.ipv6 {
		protos = append(protos, cfgVal.IPv6())
	}
	if len(protos) == 0 {
		return
	}

	for _, proto := range protos {
		if a.tcpNatOptOn == 1 {
			proto.Set(maps.CfgFlagOffsetTCPNatOptOn)
		} else if a.tcpNatOptOn == 0 {
			proto.Clear(maps.CfgFlagOffsetTCPNatOptOn)
		}

		if a.tcpNatOptWithLocalAddrOn == 1 {
			proto.Set(maps.CfgFlagOffsetTCPNatOptWithLocalAddrOn)
		} else if a.tcpNatOptWithLocalAddrOn == 0 {
			proto.Clear(maps.CfgFlagOffsetTCPNatOptWithLocalAddrOn)
		}

		if a.tcpNatOptWithLocalPortOn == 1 {
			proto.Set(maps.CfgFlagOffsetTCPNatOptWithLocalPortOn)
		} else if a.tcpNatOptWithLocalPortOn == 0 {
			proto.Clear(maps.CfgFlagOffsetTCPNatOptWithLocalPortOn)
		}

		if a.udpNatOptOn == 1 {
			proto.Set(maps.CfgFlagOffsetUDPNatOptOn)
		} else if a.udpNatOptOn == 0 {
			proto.Clear(maps.CfgFlagOffsetUDPNatOptOn)
		}

		if a.udpNatOptWithLocalAddrOn == 1 {
			proto.Set(maps.CfgFlagOffsetUDPNatOptWithLocalAddrOn)
		} else if a.udpNatOptWithLocalAddrOn == 0 {
			proto.Clear(maps.CfgFlagOffsetUDPNatOptWithLocalAddrOn)
		}

		if a.udpNatOptWithLocalPortOn == 1 {
			proto.Set(maps.CfgFlagOffsetUDPNatOptWithLocalPortOn)
		} else if a.udpNatOptWithLocalPortOn == 0 {
			proto.Clear(maps.CfgFlagOffsetUDPNatOptWithLocalPortOn)
		}
	}
}

func (a *configSetCmd) setProto(cfgVal *maps.CfgVal) {
	var protos []*maps.FlagT
	if a.ipv4 {
		protos = append(protos, cfgVal.IPv4())
	}
	if a.ipv6 {
		protos = append(protos, cfgVal.IPv6())
	}
	if len(protos) == 0 {
		return
	}

	for _, proto := range protos {
		if a.tcpProtoDenyAll == 1 {
			proto.Set(maps.CfgFlagOffsetTCPProtoDenyAll)
		} else if a.tcpProtoDenyAll == 0 {
			proto.Clear(maps.CfgFlagOffsetTCPProtoDenyAll)
		}

		if a.tcpProtoAllowAll == 1 {
			proto.Set(maps.CfgFlagOffsetTCPProtoAllowAll)
		} else if a.tcpProtoAllowAll == 0 {
			proto.Clear(maps.CfgFlagOffsetTCPProtoAllowAll)
		}

		if a.tcpProtoAllowNatEscape == 1 {
			proto.Set(maps.CfgFlagOffsetTCPProtoAllowNatEscape)
		} else if a.tcpProtoAllowNatEscape == 0 {
			proto.Clear(maps.CfgFlagOffsetTCPProtoAllowNatEscape)
		}

		if a.udpProtoDenyAll == 1 {
			proto.Set(maps.CfgFlagOffsetUDPProtoDenyAll)
		} else if a.udpProtoDenyAll == 0 {
			proto.Clear(maps.CfgFlagOffsetUDPProtoDenyAll)
		}

		if a.udpProtoAllowAll == 1 {
			proto.Set(maps.CfgFlagOffsetUDPProtoAllowAll)
		} else if a.udpProtoAllowAll == 0 {
			proto.Clear(maps.CfgFlagOffsetUDPProtoAllowAll)
		}

		if a.udpProtoAllowNatEscape == 1 {
			proto.Set(maps.CfgFlagOffsetUDPProtoAllowNatEscape)
		} else if a.udpProtoAllowNatEscape == 0 {
			proto.Clear(maps.CfgFlagOffsetUDPProtoAllowNatEscape)
		}

		if a.othProtoDenyAll == 1 {
			proto.Set(maps.CfgFlagOffsetOTHProtoDenyAll)
		} else if a.othProtoDenyAll == 0 {
			proto.Clear(maps.CfgFlagOffsetOTHProtoDenyAll)
		}
	}
}

func (a *configSetCmd) setDeny(cfgVal *maps.CfgVal) {
	var protos []*maps.FlagT
	if a.ipv4 {
		protos = append(protos, cfgVal.IPv4())
	}
	if a.ipv6 {
		protos = append(protos, cfgVal.IPv6())
	}
	if len(protos) == 0 {
		return
	}

	for _, proto := range protos {
		if a.denyAll == 1 {
			proto.Set(maps.CfgFlagOffsetDenyAll)
		} else if a.denyAll == 0 {
			proto.Clear(maps.CfgFlagOffsetDenyAll)
		}
	}
}

func (a *configSetCmd) setAllow(cfgVal *maps.CfgVal) {
	var protos []*maps.FlagT
	if a.ipv4 {
		protos = append(protos, cfgVal.IPv4())
	}
	if a.ipv6 {
		protos = append(protos, cfgVal.IPv6())
	}
	if len(protos) == 0 {
		return
	}

	for _, proto := range protos {
		if a.allowAll == 1 {
			proto.Set(maps.CfgFlagOffsetAllowAll)
		} else if a.allowAll == 0 {
			proto.Clear(maps.CfgFlagOffsetAllowAll)
		}
	}
}

func (a *configSetCmd) setTracer(cfgVal *maps.CfgVal) {
	var protos []*maps.FlagT
	if a.ipv4 {
		protos = append(protos, cfgVal.IPv4())
	}
	if a.ipv6 {
		protos = append(protos, cfgVal.IPv6())
	}
	if len(protos) == 0 {
		return
	}

	for _, proto := range protos {
		if a.traceHdrOn == 1 {
			proto.Set(maps.CfgFlagOffsetTraceHdrOn)
		} else if a.traceHdrOn == 0 {
			proto.Clear(maps.CfgFlagOffsetTraceHdrOn)
		}

		if a.traceNatOn == 1 {
			proto.Set(maps.CfgFlagOffsetTraceNatOn)
		} else if a.traceNatOn == 0 {
			proto.Clear(maps.CfgFlagOffsetTraceNatOn)
		}

		if a.traceOptOn == 1 {
			proto.Set(maps.CfgFlagOffsetTraceOptOn)
		} else if a.traceOptOn == 0 {
			proto.Clear(maps.CfgFlagOffsetTraceOptOn)
		}

		if a.traceAclOn == 1 {
			proto.Set(maps.CfgFlagOffsetTraceAclOn)
		} else if a.traceAclOn == 0 {
			proto.Clear(maps.CfgFlagOffsetTraceAclOn)
		}

		if a.traceFlowOn == 1 {
			proto.Set(maps.CfgFlagOffsetTraceFlowOn)
		} else if a.traceFlowOn == 0 {
			proto.Clear(maps.CfgFlagOffsetTraceFlowOn)
		}

		if a.traceByIpOn == 1 {
			proto.Set(maps.CfgFlagOffsetTraceByIpOn)
		} else if a.traceByIpOn == 0 {
			proto.Clear(maps.CfgFlagOffsetTraceByIpOn)
		}

		if a.traceByPortOn == 1 {
			proto.Set(maps.CfgFlagOffsetTraceByPortOn)
		} else if a.traceByPortOn == 0 {
			proto.Clear(maps.CfgFlagOffsetTraceByPortOn)
		}
	}
}
