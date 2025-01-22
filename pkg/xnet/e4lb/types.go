package e4lb

import (
	"fmt"

	"github.com/flomesh-io/xnet/pkg/logger"
)

const (
	flbDev = `flb0`
)

var (
	log = logger.New("fsm-xnet-elb")

	SysctlNetIPv4ConfArpIgnore   = fmt.Sprintf("net/ipv4/conf/%s/arp_ignore", flbDev)
	SysctlNetIPv4ConfArpAnnounce = fmt.Sprintf("net/ipv4/conf/%s/arp_announce", flbDev)
)
