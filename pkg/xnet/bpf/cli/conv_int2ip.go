package cli

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/spf13/cobra"
)

const int2ipDescription = ``
const int2ipExample = ``

type int2ipCmd struct {
	int          uint32
	littleEndian bool
}

func newInt2IP() *cobra.Command {
	int2ip := &int2ipCmd{}

	cmd := &cobra.Command{
		Use:   "int2ip",
		Short: "int2ip",
		Long:  int2ipDescription,
		Args:  cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return int2ip.run()
		},
		Example: int2ipExample,
	}

	//add flags
	f := cmd.Flags()
	f.Uint32Var(&int2ip.int, "int", 0, "--int=0")
	f.BoolVar(&int2ip.littleEndian, "little-endian", false, "--little-endian")

	return cmd
}

func (a *int2ipCmd) run() error {
	ip := make(net.IP, net.IPv4len)
	if a.littleEndian {
		binary.LittleEndian.PutUint32(ip, a.int)
	} else {
		binary.BigEndian.PutUint32(ip, a.int)
	}
	fmt.Printf("Int: %d Addr: %s\n", a.int, ip)
	return nil
}
