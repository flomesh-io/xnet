package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/ns"
	nstc "github.com/flomesh-io/xnet/pkg/xnet/tc"
)

const bpfAttachDescription = ``
const bpfAttachExample = ``

type bpfAttachCmd struct {
	netns
}

func newBpfAttach() *cobra.Command {
	bpfAttach := &bpfAttachCmd{}

	cmd := &cobra.Command{
		Use:     "attach",
		Short:   "attach",
		Long:    bpfAttachDescription,
		Aliases: []string{"a"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return bpfAttach.run()
		},
		Example: bpfAttachExample,
	}

	//add flags
	f := cmd.Flags()
	bpfAttach.addRunNetnsDirFlag(f)
	bpfAttach.addNamespaceFlag(f)
	bpfAttach.addDevFlag(f)
	return cmd
}

func (a *bpfAttachCmd) run() error {
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
		return nstc.AttachBPFProg(a.dev)
	})
	return err
}
