package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
	"github.com/flomesh-io/xnet/pkg/xnet/util"
)

const aclAddDescription = ``
const aclAddExample = ``

type aclAddCmd struct {
	sys
	sa
	proto

	acl  string
	flag uint8
	id   uint16
}

func newAclAdd() *cobra.Command {
	aclAdd := &aclAddCmd{}

	cmd := &cobra.Command{
		Use:     "add",
		Short:   "add acl",
		Long:    aclAddDescription,
		Aliases: []string{"a"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return aclAdd.run()
		},
		Example: aclAddExample,
	}

	//add flags
	f := cmd.Flags()
	aclAdd.sys.addFlags(f)
	aclAdd.sa.addFlags(f)
	aclAdd.proto.addFlags(f)
	f.Uint8Var(&aclAdd.flag, "flag", 0, "--flag=0")
	f.Uint16Var(&aclAdd.id, "id", 0, "--id=0")
	f.StringVar(&aclAdd.acl, "acl", "", "--acl=deny/audit/trusted")

	return cmd
}

func (a *aclAddCmd) run() error {
	var err error
	var aclKeys []maps.AclKey

	aclKey := maps.AclKey{}

	if !a.tcp && !a.udp {
		return errors.New("missing proto: --proto-tcp/--proto-udp")
	}

	if aclKey.Addr[0], err = util.IPv4ToInt(a.addr); err != nil {
		return err
	}

	aclKey.Port = util.HostToNetShort(a.port)

	if a.tcp {
		aclKey.Proto = uint8(maps.IPPROTO_TCP)
		aclKeys = append(aclKeys, aclKey)
	}

	if a.udp {
		aclKey.Proto = uint8(maps.IPPROTO_UDP)
		aclKeys = append(aclKeys, aclKey)
	}

	aclVal := new(maps.AclVal)
	aclVal.Flag = a.flag
	aclVal.Id = a.id
	switch a.acl {
	case `deny`:
		aclVal.Acl = uint8(maps.ACL_DENY)
	case `audit`:
		aclVal.Acl = uint8(maps.ACL_AUDIT)
	case `trusted`:
		aclVal.Acl = uint8(maps.ACL_TRUSTED)
	default:
		return fmt.Errorf(`invalid acl:%s`, a.acl)
	}

	for _, key := range aclKeys {
		if err = maps.AddAclEntry(a.sysId(), &key, aclVal); err != nil {
			return err
		}
	}

	return nil
}
