package link

import (
	"errors"

	"github.com/vishvananda/netlink"
)

func LinkTapAdd(ifName string) bool {
	if _, err := netlink.LinkByName(ifName); err != nil {
		if notFound := errors.As(err, new(netlink.LinkNotFoundError)); notFound {
			ret := linkTapAdd(ifName)
			return ret == 0
		} else {
			return false
		}
	} else {
		return true
	}
}
