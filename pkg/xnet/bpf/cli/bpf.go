package cli

import (
	"github.com/spf13/cobra"
)

const bpfDescription = ``

func NewBpfCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bpf",
		Short: "bpf",
		Long:  bpfDescription,
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newBpfList())
	cmd.AddCommand(newBpfAttach())
	cmd.AddCommand(newBpfDetach())
	cmd.AddCommand(newBpfMount())

	return cmd
}
