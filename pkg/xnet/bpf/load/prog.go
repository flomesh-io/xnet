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
	if cfgVal, cfgErr := maps.GetXNetCfg(); cfgErr != nil {
		log.Fatal().Msg(cfgErr.Error())
	} else {
		if !cfgVal.IsSet(maps.CfgFlagOffsetIPv4UDPProtoAllowAll) {
			if !cfgVal.IsSet(maps.CfgFlagOffsetIPv4UDPProtoDenyAll) &&
				!cfgVal.IsSet(maps.CfgFlagOffsetIPv4UDPNatByIpPortOn) &&
				!cfgVal.IsSet(maps.CfgFlagOffsetIPv4UDPNatByIpOn) &&
				!cfgVal.IsSet(maps.CfgFlagOffsetIPv4UDPNatByPortOn) &&
				!cfgVal.IsSet(maps.CfgFlagOffsetIPv4UDPNatAllOff) {
				cfgVal.Set(maps.CfgFlagOffsetIPv4UDPProtoAllowAll)
			}
		}
		cfgVal.Set(maps.CfgFlagOffsetIPv4AclCheckOn)
		if cfgErr = maps.SetXNetCfg(cfgVal); cfgErr != nil {
			log.Fatal().Msg(cfgErr.Error())
		}
	}
}
