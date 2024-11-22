package cli

import (
	"fmt"
	"net"
	"os"
	"strings"

	gotc "github.com/florianl/go-tc"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/ns"
	nstc "github.com/flomesh-io/xnet/pkg/xnet/tc"
)

const netnsListDescription = ``
const netnsListExample = ``

type netnsListCmd struct {
	netns
}

func newNetnsList() *cobra.Command {
	netnsList := &netnsListCmd{}

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "list",
		Long:    netnsListDescription,
		Aliases: []string{"l", "ls"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return netnsList.run()
		},
		Example: netnsListExample,
	}

	//add flags
	f := cmd.Flags()
	netnsList.addRunNetnsDirFlag(f)
	netnsList.addDevFlag(f)
	return cmd
}

func (a *netnsListCmd) run() error {
	if err := a.validateRunNetnsDirFlag(); err != nil {
		return err
	}
	if err := a.validateDevFlag(); err != nil {
		return err
	}
	rd, err := os.ReadDir(a.runNetnsDir)
	if err != nil {
		return err
	}
	for _, fi := range rd {
		if fi.IsDir() {
			continue
		}
		inode := fmt.Sprintf(`%s/%s`, a.runNetnsDir, fi.Name())
		netNS, nsErr := ns.GetNS(inode)
		if nsErr != nil {
			fmt.Println(nsErr.Error())
			continue
		}
		if nsErr = netNS.Do(func(_ ns.NetNS) error {
			fmt.Print("netns: ", fi.Name())
			fmt.Print(" dev: ", a.dev)
			if iface, ifaceErr := net.InterfaceByName(a.dev); ifaceErr != nil {
				return ifaceErr
			} else {
				fmt.Printf(" hwAddr:[ %v ]", iface.HardwareAddr.String())
				if addrs, e := iface.Addrs(); e != nil {
					return e
				} else {
					fmt.Print(" addrs:[")
					for _, addr := range addrs {
						if !strings.Contains(addr.String(), `::`) {
							fmt.Printf(" %18s", addr)
						}
					}
					fmt.Print("]")
				}

				if rtnl, rtnlErr := gotc.Open(&gotc.Config{}); rtnlErr == nil {
					if qdisc, _ := nstc.GetBPFQdisc(rtnl, uint32(iface.Index)); qdisc != nil {
						hasIngressFilter := false
						fmt.Print(` {`)
						if filter, _ := nstc.GetBPFFilter(rtnl, uint32(iface.Index), nstc.HandleIngress); filter != nil {
							hasIngressFilter = true
							fmt.Printf(`"ingress":"%s"`, *filter.Attribute.BPF.Name)
						}

						if filter, _ := nstc.GetBPFFilter(rtnl, uint32(iface.Index), nstc.HandleEgress); filter != nil {
							if hasIngressFilter {
								fmt.Print(`,`)
							}
							fmt.Printf(`"egress":"%s"`, *filter.Attribute.BPF.Name)
						}
						fmt.Print(`}`)
					}
					if err = rtnl.Close(); err != nil {
						log.Error().Msgf("could not close rtnetlink socket: %v\n", err)
					}
				}
				fmt.Print("\n")
			}
			return nil
		}); nsErr != nil {
			fmt.Println(" ", nsErr.Error())
		}
	}
	return nil
}
