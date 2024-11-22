package cli

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/util"
)

const ip2intDescription = ``
const ip2intExample = ``

type ip2intCmd struct {
	addr         net.IP
	littleEndian bool
}

func newIP2Int() *cobra.Command {
	ip2int := &ip2intCmd{}

	cmd := &cobra.Command{
		Use:   "ip2int",
		Short: "ip2int",
		Long:  ip2intDescription,
		Args:  cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return ip2int.run()
		},
		Example: ip2intExample,
	}

	//add flags
	f := cmd.Flags()
	f.IPVar(&ip2int.addr, "addr", net.ParseIP("0.0.0.0"), "--addr=0.0.0.0")
	f.BoolVar(&ip2int.littleEndian, "little-endian", false, "--little-endian")

	return cmd
}

func (a *ip2intCmd) run() error {
	if a.addr.To4() == nil {
		return util.ErrNotIPv4Address
	}
	ipInt := uint32(0)
	if a.littleEndian {
		ipInt = binary.LittleEndian.Uint32(a.addr.To4())
	} else {
		ipInt = binary.BigEndian.Uint32(a.addr.To4())
	}
	fmt.Printf("Addr: %s Int: %d\n", a.addr.String(), ipInt)
	return nil
}
