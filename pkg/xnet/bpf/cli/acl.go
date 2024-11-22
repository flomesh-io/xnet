package cli

import (
	"github.com/spf13/cobra"
)

const aclDescription = ``

func NewAclCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "acl",
		Short: "acl",
		Long:  aclDescription,
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newAclList())
	cmd.AddCommand(newAclAdd())
	cmd.AddCommand(newAclDel())

	return cmd
}
