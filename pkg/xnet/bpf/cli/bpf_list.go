package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/ns"
	nstc "github.com/flomesh-io/xnet/pkg/xnet/tc"
)

const bpfListDescription = ``
const bpfListExample = ``

type bpfListCmd struct {
	netns
}

func newBpfList() *cobra.Command {
	bpfList := &bpfListCmd{}

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "list",
		Long:    bpfListDescription,
		Aliases: []string{"l", "ls"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return bpfList.run()
		},
		Example: bpfListExample,
	}

	//add flags
	f := cmd.Flags()
	bpfList.addRunNetnsDirFlag(f)
	bpfList.addNamespaceFlag(f)
	bpfList.addDevFlag(f)
	return cmd
}

func (a *bpfListCmd) run() error {
	if err := a.validateRunNetnsDirFlag(); err != nil {
		return err
	}
	if err := a.validateNamespaceFlag(); err != nil {
		return err
	}
	if err := a.validateDevFlag(); err != nil {
		return err
	}
	inode := fmt.Sprintf(`%s/%s`, a.runNetnsDir, a.namespace)
	namespace, err := ns.GetNS(inode)
	if err != nil {
		return err
	}

	err = namespace.Do(func(_ ns.NetNS) error {
		return nstc.ShowBPFProg(a.dev)
	})
	return err
}
