package cli

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"

	"github.com/flomesh-io/xnet/pkg/signals"
	"github.com/flomesh-io/xnet/pkg/xnet/arp"
)

const arpAnnounceDescription = ``
const arpAnnounceExample = ``

type arpAnnounceCmd struct {
	arpEntry
}

func newArpAnnounce() *cobra.Command {
	arpAnnounce := &arpAnnounceCmd{}

	cmd := &cobra.Command{
		Use:     "announce",
		Short:   "announce arp",
		Long:    arpAnnounceDescription,
		Aliases: []string{"an"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return arpAnnounce.run()
		},
		Example: arpAnnounceExample,
	}

	//add flags
	f := cmd.Flags()
	arpAnnounce.arpEntry.addFlags(f)
	return cmd
}

func (a *arpAnnounceCmd) run() error {
	if a.addr.IsUnspecified() {
		return fmt.Errorf(`invalid arp addr: %s`, a.addr)
	}
	mac, macErr := net.ParseMAC(a.mac)
	if macErr != nil {
		return fmt.Errorf(`invalid arp mac address: %s`, a.mac)
	}
	neighMac, neighMacErr := net.ParseMAC(a.neighMac)
	if neighMacErr != nil {
		return fmt.Errorf(`invalid neigh mac address: %s`, a.neighMac)
	}

	_, cancel := context.WithCancel(context.Background())
	stop := signals.RegisterExitHandlers(cancel)

	scheduleTimer := time.NewTimer(time.Second * 1)
	defer scheduleTimer.Stop()
	for {
		select {
		case <-stop:
			return nil
		case <-scheduleTimer.C:
			if iface, err := net.InterfaceByName(a.dev); err == nil {
				neigh := &netlink.Neigh{
					LinkIndex:    iface.Index,
					State:        arp.NUD_REACHABLE,
					IP:           a.addr,
					HardwareAddr: neighMac,
				}
				if err = netlink.NeighSet(neigh); err != nil {
					log.Error().Msg(err.Error())
					if err = netlink.NeighAdd(neigh); err != nil {
						log.Error().Msg(err.Error())
					}
				}
				if err = arp.Announce(a.dev, a.addr.String(), mac); err != nil {
					log.Error().Msg(err.Error())
				}
				scheduleTimer.Reset(time.Second * 5)
			} else {
				return err
			}
		}
	}
}
