package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/cli"
)

var globalUsage = ``

func newRootCmd(args []string) *cobra.Command {
	cmd := &cobra.Command{
		Use:          "xnat",
		Short:        "Manage Flomesh Sidecar Policies.",
		Long:         globalUsage,
		SilenceUsage: true,
	}

	// Add subcommands here
	cmd.AddCommand(
		cli.NewBpfCmd(),
		cli.NewProgCmd(),
		cli.NewConfigCmd(),
		cli.NewNatCmd(),
		cli.NewAclCmd(),
		cli.NewTraceCmd(),
		cli.NewFlowCmd(),
		cli.NewOptCmd(),
		cli.NewNetnsCmd(),
		cli.NewConvCmd(),
	)

	_ = cmd.PersistentFlags().Parse(args)
	return cmd
}

func initCommands() *cobra.Command {
	return newRootCmd(os.Args[1:])
}

func main() {
	cmd := initCommands()
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
