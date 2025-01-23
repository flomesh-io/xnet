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
	sys
	netns
	tc
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
	bpfAttach.sys.addFlags(f)
	bpfAttach.addRunNetnsDirFlag(f)
	bpfAttach.addNamespaceFlag(f)
	bpfAttach.addDevFlag(f)
	bpfAttach.tc.addFlags(f)
	return cmd
}

func (a *bpfAttachCmd) run() error {
	if err := a.validateDevFlag(); err != nil {
		return err
	}

	if len(a.namespace) > 0 {
		if err := a.validateRunNetnsDirFlag(); err != nil {
			return err
		}

		inode := fmt.Sprintf(`%s/%s`, a.runNetnsDir, a.namespace)
		namespace, err := ns.GetNS(inode)
		if err != nil {
			return err
		}

		return namespace.Do(func(_ ns.NetNS) error {
			return nstc.AttachBPFProg(a.sysId(), a.dev, a.tcIngress, a.tcEgress)
		})
	} else {
		return nstc.AttachBPFProg(a.sysId(), a.dev, a.tcIngress, a.tcEgress)
	}
}
