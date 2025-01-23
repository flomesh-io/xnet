package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
)

const natDelDescription = ``
const natDelExample = ``

type natDelCmd struct {
	sys
	nat
}

func newNatDel() *cobra.Command {
	natDel := &natDelCmd{}

	cmd := &cobra.Command{
		Use:     "del",
		Short:   "del nat",
		Long:    natDelDescription,
		Aliases: []string{"d"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return natDel.run()
		},
		Example: natDelExample,
	}

	//del flags
	f := cmd.Flags()
	natDel.sys.addFlags(f)
	natDel.sa.addFlags(f)
	natDel.proto.addFlags(f)
	natDel.tc.addFlags(f)
	natDel.ep.addFlags(f, false, false)

	return cmd
}

func (a *natDelCmd) run() error {
	if natKeys, err := a.getKeys(); err != nil {
		return err
	} else {
		if a.ep.addr.IsUnspecified() || a.ep.port == 0 {
			for _, natKey := range natKeys {
				if err = maps.DelNatEntry(a.sysId(), &natKey); err != nil {
					fmt.Println(err.Error())
				}
			}
		} else {
			for _, natKey := range natKeys {
				natVal, _ := maps.GetNatEntry(a.sysId(), &natKey)
				if err = natVal.DelEp(a.ep.addr, a.ep.port); err != nil {
					fmt.Printf(`del ep addr: %s port: %d fail: %s\n`, a.ep.addr, a.ep.port, err.Error())
				} else {
					if err = maps.AddNatEntry(a.sysId(), &natKey, natVal); err != nil {
						fmt.Printf(`del nat: {"key":%s,"value":%s} fail: %s`, natKey.String(), natVal.String(), err.Error())
					}
				}
			}
		}
		return nil
	}
}
