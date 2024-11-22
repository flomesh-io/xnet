package cli

import (
	"encoding/binary"
	"fmt"

	"github.com/spf13/cobra"
)

const htonsDescription = ``
const htonsExample = ``

type htonsCmd struct {
	int uint16
}

func newHtons() *cobra.Command {
	htons := &htonsCmd{}

	cmd := &cobra.Command{
		Use:   "htons",
		Short: "htons",
		Long:  htonsDescription,
		Args:  cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return htons.run()
		},
		Example: htonsExample,
	}

	//add flags
	f := cmd.Flags()
	f.Uint16Var(&htons.int, "int", 0, "--int=0")

	return cmd
}

func (a *htonsCmd) run() error {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, a.int)
	fmt.Printf("Int: %d htons: %d\n", a.int, binary.BigEndian.Uint16(b))
	return nil
}
