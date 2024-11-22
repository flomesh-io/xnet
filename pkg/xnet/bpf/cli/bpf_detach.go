package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/ns"
	nstc "github.com/flomesh-io/xnet/pkg/xnet/tc"
)

const bpfDetachDescription = ``
const bpfDetachExample = ``

type bpfDetachCmd struct {
	netns
}

func newBpfDetach() *cobra.Command {
	bpfDetach := &bpfDetachCmd{}

	cmd := &cobra.Command{
		Use:     "detach",
		Short:   "detach",
		Long:    bpfDetachDescription,
		Aliases: []string{"a"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return bpfDetach.run()
		},
		Example: bpfDetachExample,
	}

	//add flags
	f := cmd.Flags()
	bpfDetach.addRunNetnsDirFlag(f)
	bpfDetach.addNamespaceFlag(f)
	bpfDetach.addDevFlag(f)
	return cmd
}

func (a *bpfDetachCmd) run() error {
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
		return nstc.DetachBPFProg(a.dev)
	})
	return err
}
