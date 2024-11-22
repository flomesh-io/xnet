package cli

import (
	"encoding/binary"
	"fmt"

	"github.com/spf13/cobra"
)

const ntohsDescription = ``
const ntohsExample = ``

type ntohsCmd struct {
	int uint16
}

func newNtohs() *cobra.Command {
	ntohs := &ntohsCmd{}

	cmd := &cobra.Command{
		Use:   "ntohs",
		Short: "ntohs",
		Long:  ntohsDescription,
		Args:  cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return ntohs.run()
		},
		Example: ntohsExample,
	}

	//add flags
	f := cmd.Flags()
	f.Uint16Var(&ntohs.int, "int", 0, "--int=0")

	return cmd
}

func (a *ntohsCmd) run() error {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, a.int)
	fmt.Printf("Int: %d ntohs: %d\n", a.int, binary.LittleEndian.Uint16(b))
	return nil
}
