// Package main implements fsm cni plugin.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	cniv "github.com/containernetworking/cni/pkg/version"

	"github.com/flomesh-io/xnet/pkg/logger"
	"github.com/flomesh-io/xnet/pkg/version"
	"github.com/flomesh-io/xnet/pkg/xnet/cni/plugin"
	"github.com/flomesh-io/xnet/pkg/xnet/util"
)

var (
	log = logger.New("fsm-xnet-cni-plugin")
)

func init() {
	var err error
	cfg := plugin.Config{}
	conf := plugin.GetConfig()
	if util.Exists(conf) {
		//#nosec G304
		if bytes, ioErr := os.ReadFile(conf); ioErr == nil {
			err = json.Unmarshal(bytes, &cfg)
		}
	}
	if len(cfg.LogFile) == 0 {
		cfg.LogFile = `/tmp/xcni.log`
	}
	if len(cfg.LogLevel) == 0 {
		cfg.LogLevel = `warn`
	}
	plugin.SetLogFile(cfg.LogFile)
	if logErr := logger.SetLogLevel(cfg.LogLevel); logErr != nil {
		_ = logger.SetLogLevel(`warn`)
	}
	if err != nil {
		log.Error().Err(err).Msg(`invalid xcni config.`)
	}
}

func main() {
	log.Info().Msgf("fsm xcni %s; %s; %s", version.Version, version.GitCommit, version.BuildDate)
	skel.PluginMainFuncs(skel.CNIFuncs{
		Add:   plugin.CmdAdd,
		Check: plugin.CmdCheck,
		Del:   plugin.CmdDelete,
	},
		cniv.All,
		fmt.Sprintf("fsm xcni %s; %s; %s", version.Version, version.GitCommit, version.BuildDate),
	)
}
