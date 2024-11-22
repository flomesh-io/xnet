package cli

import (
	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
)

const aclListDescription = ``
const aclListExample = ``

type aclListCmd struct {
}

func newAclList() *cobra.Command {
	aclList := &aclListCmd{}

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "list acls",
		Long:    aclListDescription,
		Aliases: []string{"l", "ls"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return aclList.run()
		},
		Example: aclListExample,
	}

	return cmd
}

func (a *aclListCmd) run() error {
	maps.ShowAclEntries()
	return nil
}
