package e4lb

import (
	"net"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
	"github.com/flomesh-io/xnet/pkg/xnet/sysctl"
	"github.com/flomesh-io/xnet/pkg/xnet/tc"
	"github.com/flomesh-io/xnet/pkg/xnet/util/link"
	"github.com/flomesh-io/xnet/pkg/xnet/util/route"
)

func BridgeOn() {
	if success := link.LinkTapAdd(flbDev); !success {
		log.Fatal().Msgf("fail to add %s link", flbDev)
	} else {
		if iface, ifaceErr := net.InterfaceByName(flbDev); ifaceErr != nil {
			log.Fatal().Err(ifaceErr).Msgf("fail to find %s link", flbDev)
		} else {
			if attachErr := tc.AttachBPFProg(maps.SysNoop, flbDev, true, true); attachErr != nil {
				log.Fatal().Err(attachErr).Msgf("fail to attach %s link: %d", flbDev, iface.Index)
			}
		}
	}
	sysctl := sysctl.New()
	if err := sysctl.SetSysctl(SysctlNetIPv4ConfArpIgnore, 1); err != nil {
		log.Fatal().Err(err).Msgf("fail to set sysctl: %s", SysctlNetIPv4ConfArpIgnore)
	}
	if err := sysctl.SetSysctl(SysctlNetIPv4ConfArpAnnounce, 2); err != nil {
		log.Fatal().Err(err).Msgf("fail to set sysctl: %s", SysctlNetIPv4ConfArpAnnounce)
	}
}

func E4lbOn() {
	dev, _, err := route.DiscoverGateway()
	if err != nil {
		log.Fatal().Err(err).Msg("fail to find default net device.")
	}

	if iface, ifaceErr := net.InterfaceByName(dev); ifaceErr != nil {
		log.Fatal().Err(ifaceErr).Msgf("fail to find %s link", dev)
	} else {
		if attachErr := tc.AttachBPFProg(maps.SysE4lb, dev, true, true); attachErr != nil {
			log.Fatal().Err(attachErr).Msgf("fail to attach %s link: %d", dev, iface.Index)
		}
	}
}

func E4lbOff() {
	dev, _, err := route.DiscoverGateway()
	if err != nil {
		log.Error().Err(err).Msg("fail to find default net device.")
		return
	}

	if iface, ifaceErr := net.InterfaceByName(dev); ifaceErr != nil {
		log.Error().Err(ifaceErr).Msgf("fail to find %s link", dev)
	} else {
		if detachErr := tc.DetachBPFProg(maps.SysE4lb, dev, true, true); detachErr != nil {
			log.Error().Err(detachErr).Msgf("fail to detach %s link: %d", dev, iface.Index)
		}
	}
}
