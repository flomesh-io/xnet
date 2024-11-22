package cli

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
	"github.com/flomesh-io/xnet/pkg/xnet/util"
)

const natDescription = ``

func NewNatCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "nat",
		Short: "nat",
		Long:  natDescription,
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newNatList())
	cmd.AddCommand(newNatGet())
	cmd.AddCommand(newNatAdd())
	cmd.AddCommand(newNatDel())

	return cmd
}

type nat struct {
	sa
	proto
	tc
	ep
}

func (c *nat) getKeys() ([]maps.NatKey, error) {
	var err error
	natKey := maps.NatKey{V6: 0}
	if natKey.Daddr[0], err = util.IPv4ToInt(c.sa.addr); err != nil {
		return nil, err
	}
	natKey.Dport = util.HostToNetShort(c.sa.port)

	if !c.tcp && !c.udp {
		return nil, errors.New("missing proto: --proto-tcp/--proto-udp")
	}

	if !c.tcIngress && !c.tcEgress {
		return nil, errors.New("missing tc direct: --tc-ingress/--tc-egress")
	}

	var keys []maps.NatKey
	if c.tcp {
		natKey.Proto = uint8(maps.IPPROTO_TCP)
		if c.tcIngress {
			natKey.TcDir = uint8(maps.TC_DIR_IGR)
			keys = append(keys, natKey)
		}
		if c.tcEgress {
			natKey.TcDir = uint8(maps.TC_DIR_EGR)
			keys = append(keys, natKey)
		}
	}

	if c.udp {
		natKey.Proto = uint8(maps.IPPROTO_UDP)
		if c.tcIngress {
			natKey.TcDir = uint8(maps.TC_DIR_IGR)
			keys = append(keys, natKey)
		}
		if c.tcEgress {
			natKey.TcDir = uint8(maps.TC_DIR_EGR)
			keys = append(keys, natKey)
		}
	}

	return keys, nil
}
