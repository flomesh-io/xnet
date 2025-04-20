package e4lb

import (
	"net"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
	"github.com/flomesh-io/xnet/pkg/xnet/tc"
	"github.com/flomesh-io/xnet/pkg/xnet/util/route"
)

func E4lbOn() bool {
	dev, _, err := route.DiscoverGateway()
	if err != nil {
		log.Fatal().Err(err).Msg("fail to find default net device.")
	}

	if iface, ifaceErr := net.InterfaceByName(dev); ifaceErr != nil {
		log.Fatal().Err(ifaceErr).Msgf("fail to find %s link", dev)
	} else {
		if attachErr := tc.AttachBPFProg(maps.SysE4lb, dev, true, true); attachErr != nil {
			log.Error().Err(attachErr).Msgf("fail to attach %s link: %d", dev, iface.Index)
			return false
		}
	}
	return true
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
