package cli

import (
	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/fs"
)

const bpfMountDescription = ``
const bpfMountExample = ``

func newBpfMount() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "mount",
		Short:   "mount",
		Long:    bpfMountDescription,
		Aliases: []string{"m", "mnt"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fs.Mount()
		},
		Example: bpfMountExample,
	}

	return cmd
}
