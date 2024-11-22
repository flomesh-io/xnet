package util

import (
	"errors"
	"net"
	"syscall"

	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func GetDefaultGatewayAddr(iface net.Interface) (net.IP, error) {
	nlLink, err := netlink.LinkByName(iface.Name)
	if err != nil {
		return nil, err
	}
	nlHandle, err := netlink.NewHandle(syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}

	retries := 3
	for retries > 0 {
		routes, err := nlHandle.RouteList(nlLink, syscall.AF_INET)
		if err != nil {
			if errors.Is(err, unix.EINTR) && retries > 0 {
				log.Debug().Msgf("listing routes for interface %s, family %d hit EINTR. Retrying", nlLink.Attrs().Name, syscall.AF_INET)
				retries--
				continue
			}
		}

		for _, route := range routes {
			if route.Gw != nil && route.Dst != nil && route.Dst.IP.IsUnspecified() {
				return route.Gw, nil
			}
		}
	}
	return nil, nil
}
