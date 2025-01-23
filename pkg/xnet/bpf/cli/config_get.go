package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
)

const configGetDescription = ``
const configGetExample = ``

type configGetCmd struct {
	sys
}

func newConfigGet() *cobra.Command {
	configGet := &configGetCmd{}

	cmd := &cobra.Command{
		Use:     "get",
		Short:   "get global configurations",
		Long:    configGetDescription,
		Aliases: []string{"g"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return configGet.run()
		},
		Example: configGetExample,
	}

	//add flags
	f := cmd.Flags()
	configGet.sys.addFlags(f)

	return cmd
}

func (a *configGetCmd) run() error {
	if cfgVal, err := maps.GetXNetCfg(a.sysId()); err == nil {
		fmt.Printf(`{"sys":"%s","config":%s}`, maps.SysName(a.sysId()), cfgVal.String())
	}
	return nil
}
