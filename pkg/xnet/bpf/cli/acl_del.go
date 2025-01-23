package cli

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
	"github.com/flomesh-io/xnet/pkg/xnet/util"
)

const aclDelDescription = ``
const aclDelExample = ``

type aclDelCmd struct {
	sys
	sa
	proto
}

func newAclDel() *cobra.Command {
	aclDel := &aclDelCmd{}

	cmd := &cobra.Command{
		Use:     "del",
		Short:   "del acl",
		Long:    aclDelDescription,
		Aliases: []string{"d"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return aclDel.run()
		},
		Example: aclDelExample,
	}

	//add flags
	f := cmd.Flags()
	aclDel.sys.addFlags(f)
	aclDel.sa.addFlags(f)
	aclDel.proto.addFlags(f)

	return cmd
}

func (a *aclDelCmd) run() error {
	var err error

	aclKey := new(maps.AclKey)

	if !a.tcp && !a.udp {
		return errors.New("missing proto: --proto-tcp/--proto-udp")
	}

	if aclKey.Addr[0], err = util.IPv4ToInt(a.addr); err != nil {
		return err
	}

	aclKey.Port = util.HostToNetShort(a.port)

	if a.tcp {
		aclKey.Proto = uint8(maps.IPPROTO_TCP)
		if err = maps.DelAclEntry(a.sysId(), aclKey); err != nil {
			return err
		}
	}

	if a.udp {
		aclKey.Proto = uint8(maps.IPPROTO_UDP)
		if err = maps.DelAclEntry(a.sysId(), aclKey); err != nil {
			return err
		}
	}

	return nil
}
