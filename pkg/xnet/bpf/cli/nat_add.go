package cli

import (
	"fmt"
	"net"

	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
)

const natAddDescription = ``
const natAddExample = ``

type natAddCmd struct {
	nat
}

func newNatAdd() *cobra.Command {
	natAdd := &natAddCmd{}

	cmd := &cobra.Command{
		Use:     "add",
		Short:   "add nat",
		Long:    natAddDescription,
		Aliases: []string{"a"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return natAdd.run()
		},
		Example: natAddExample,
	}

	//add flags
	f := cmd.Flags()
	natAdd.sa.addFlags(f)
	natAdd.proto.addFlags(f)
	natAdd.tc.addFlags(f)
	natAdd.ep.addFlags(f, true, true)

	return cmd
}

func (a *natAddCmd) run() error {
	if natKeys, err := a.getKeys(); err != nil {
		return err
	} else {
		if a.ep.addr.IsUnspecified() {
			return fmt.Errorf(`invalid ep addr: %s`, a.ep.addr)
		}
		if a.ep.port == 0 {
			return fmt.Errorf(`invalid ep port: %d`, a.ep.port)
		}
		mac, macErr := net.ParseMAC(a.ep.mac)
		if macErr != nil {
			return fmt.Errorf(`invalid ep MAC address: %s`, a.ep.mac)
		}
		for _, natKey := range natKeys {
			natVal, _ := maps.GetNatEntry(&natKey)
			if _, err = natVal.AddEp(a.ep.addr, a.ep.port, mac, a.inactive); err != nil {
				fmt.Printf(`add ep addr: %s port: %d fail: %s\n`, a.ep.addr, a.ep.port, err.Error())
			} else {
				if err = maps.AddNatEntry(&natKey, natVal); err != nil {
					fmt.Printf(`add nat: {"key":%s,"value":%s} fail: %s`, natKey.String(), natVal.String(), err.Error())
				}
			}
		}
		return nil
	}
}
