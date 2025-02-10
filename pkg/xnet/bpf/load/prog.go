package load

import (
	"os/exec"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/fs"
	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
	"github.com/flomesh-io/xnet/pkg/xnet/util"
)

const (
	bpftoolCmd = `/usr/local/bin/bpftool`
)

func ProgLoadAll() {
	pinningDir := fs.GetPinningDir()
	if exists := util.Exists(pinningDir); exists {
		return
	}
	args := []string{
		`prog`,
		`loadall`,
		bpfProgPath,
		pinningDir,
		`pinmaps`,
		pinningDir,
	}
	cmd := exec.Command(bpftoolCmd, args...) // nolint gosec
	output, err := cmd.Output()
	if err != nil {
		log.Debug().Msg(err.Error())
	} else if len(output) > 0 {
		log.Debug().Msg(string(output))
	}

	maps.InitProgEntries()
}

func InitMeshConfig() {
	if cfgVal, cfgErr := maps.GetXNetCfg(maps.SysMesh); cfgErr != nil {
		log.Fatal().Msg(cfgErr.Error())
	} else {
		if !cfgVal.IPv4().IsSet(maps.CfgFlagOffsetUDPProtoAllowAll) {
			if !cfgVal.IPv4().IsSet(maps.CfgFlagOffsetUDPProtoDenyAll) &&
				!cfgVal.IPv4().IsSet(maps.CfgFlagOffsetUDPNatByIpPortOn) &&
				!cfgVal.IPv4().IsSet(maps.CfgFlagOffsetUDPNatByIpOn) &&
				!cfgVal.IPv4().IsSet(maps.CfgFlagOffsetUDPNatByPortOn) &&
				!cfgVal.IPv4().IsSet(maps.CfgFlagOffsetUDPNatAllOff) {
				cfgVal.IPv4().Set(maps.CfgFlagOffsetUDPProtoAllowAll)
			}
		}
		cfgVal.IPv4().Set(maps.CfgFlagOffsetAclCheckOn)
		if cfgErr = maps.SetXNetCfg(maps.SysMesh, cfgVal); cfgErr != nil {
			log.Fatal().Msg(cfgErr.Error())
		}
	}
}

func InitE4lbConfig(enableE4lbIPv4, enableE4lbIPv6 bool) {
	if cfgVal, cfgErr := maps.GetXNetCfg(maps.SysE4lb); cfgErr != nil {
		log.Fatal().Msg(cfgErr.Error())
	} else {
		if enableE4lbIPv4 {
			cfgVal.IPv4().Set(maps.CfgFlagOffsetTCPNatAllOff)
			cfgVal.IPv4().Set(maps.CfgFlagOffsetTCPNatByIpPortOn)
			cfgVal.IPv4().Set(maps.CfgFlagOffsetTCPProtoAllowNatEscape)
			cfgVal.IPv4().Set(maps.CfgFlagOffsetUDPProtoAllowAll)
			cfgVal.IPv4().Clear(maps.CfgFlagOffsetOTHProtoDenyAll)
		} else {
			cfgVal.IPv4().Clear(maps.CfgFlagOffsetDenyAll)
		}

		if enableE4lbIPv6 {
			cfgVal.IPv6().Set(maps.CfgFlagOffsetTCPNatAllOff)
			cfgVal.IPv6().Set(maps.CfgFlagOffsetTCPNatByIpPortOn)
			cfgVal.IPv6().Set(maps.CfgFlagOffsetTCPProtoAllowNatEscape)
			cfgVal.IPv6().Set(maps.CfgFlagOffsetUDPProtoAllowAll)
			cfgVal.IPv6().Clear(maps.CfgFlagOffsetOTHProtoDenyAll)
		} else {
			cfgVal.IPv6().Clear(maps.CfgFlagOffsetDenyAll)
		}

		if cfgErr = maps.SetXNetCfg(maps.SysE4lb, cfgVal); cfgErr != nil {
			log.Fatal().Msg(cfgErr.Error())
		}
	}
}
