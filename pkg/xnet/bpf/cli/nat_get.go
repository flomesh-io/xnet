package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
)

const natGetDescription = ``
const natGetExample = ``

type natGetCmd struct {
	sys
	nat
}

func newNatGet() *cobra.Command {
	natGet := &natGetCmd{}

	cmd := &cobra.Command{
		Use:     "get",
		Short:   "get nat",
		Long:    natGetDescription,
		Aliases: []string{"g"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return natGet.run()
		},
		Example: natGetExample,
	}

	//add flags
	f := cmd.Flags()
	natGet.sys.addFlags(f)
	natGet.sa.addFlags(f)
	natGet.proto.addFlags(f)
	natGet.tc.addFlags(f)

	return cmd
}

func (a *natGetCmd) run() error {
	if natKeys, err := a.getKeys(); err != nil {
		return err
	} else {
		first := true
		fmt.Println("[")
		for _, natKey := range natKeys {
			if first {
				first = false
			} else {
				fmt.Println(`,`)
			}
			if natVal, err := maps.GetNatEntry(a.sysId(), &natKey); err == nil {
				fmt.Printf(`{"key":%s,"value":%s}`, natKey.String(), natVal.String())
			} else {
				fmt.Printf(`{"key":%s,"value":"%s"}`, natKey.String(), err.Error())
			}
		}
		fmt.Println()
		fmt.Println(`]`)
		return nil
	}
}
