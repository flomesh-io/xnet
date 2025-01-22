package cli

import (
	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
)

const configListDescription = ``
const configListExample = ``

type configListCmd struct {
}

func newConfigList() *cobra.Command {
	configList := &configListCmd{}

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "list global configurations",
		Long:    configListDescription,
		Aliases: []string{"l", "ls"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return configList.run()
		},
		Example: configListExample,
	}

	return cmd
}

func (a *configListCmd) run() error {
	maps.ShowCfgEntries()
	return nil
}
