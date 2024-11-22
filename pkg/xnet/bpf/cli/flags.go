package cli

import (
	"fmt"
	"net"

	flag "github.com/spf13/pflag"

	"github.com/flomesh-io/xnet/pkg/xnet/util"
)

type tc struct {
	tcIngress bool
	tcEgress  bool
}

func (c *tc) addFlags(f *flag.FlagSet) {
	f.BoolVar(&c.tcIngress, "tc-ingress", false, "--tc-ingress")
	f.BoolVar(&c.tcEgress, "tc-egress", false, "--tc-egress")
}

type proto struct {
	tcp bool
	udp bool
}

func (c *proto) addFlags(f *flag.FlagSet) {
	f.BoolVar(&c.tcp, "proto-tcp", false, "--proto-tcp")
	f.BoolVar(&c.udp, "proto-udp", false, "--proto-udp")
}

type sa struct {
	addr net.IP
	port uint16
}

func (c *sa) addFlags(f *flag.FlagSet) {
	f.IPVar(&c.addr, "addr", net.ParseIP("0.0.0.0"), "--addr=0.0.0.0")
	f.Uint16Var(&c.port, "port", 0, "--port=0")
}

func (c *sa) addAddrFlag(f *flag.FlagSet) {
	f.IPVar(&c.addr, "addr", net.ParseIP("0.0.0.0"), "--addr=0.0.0.0")
}

func (c *sa) addPortFlag(f *flag.FlagSet) {
	f.Uint16Var(&c.port, "port", 0, "--port=0")
}

type ep struct {
	addr     net.IP
	port     uint16
	mac      string
	inactive bool
}

func (c *ep) addFlags(f *flag.FlagSet, mac, inactive bool) {
	f.IPVar(&c.addr, "ep-addr", net.ParseIP("0.0.0.0"), "--ep-addr=0.0.0.0")
	f.Uint16Var(&c.port, "ep-port", 0, "--ep-port=0")
	if mac {
		f.StringVar(&c.mac, "ep-mac", "", "--ep-mac=00:00:00:00:00:00")
	}
	if inactive {
		f.BoolVar(&c.inactive, "inactive", false, "--inactive")
	}
}

type netns struct {
	runNetnsDir string
	namespace   string
	dev         string
}

func (c *netns) addRunNetnsDirFlag(f *flag.FlagSet) {
	f.StringVar(&c.runNetnsDir, "run-netns-dir", "", "--run-netns-dir=/run/netns")
}

func (c *netns) addNamespaceFlag(f *flag.FlagSet) {
	f.StringVar(&c.namespace, "namespace", "", "--namespace=xx")
}

func (c *netns) addDevFlag(f *flag.FlagSet) {
	f.StringVar(&c.dev, "dev", "eth0", "--dev=eth0")
}

func (c *netns) validateRunNetnsDirFlag() error {
	if len(c.runNetnsDir) > 0 {
		if exists := util.Exists(c.runNetnsDir); !exists {
			return fmt.Errorf(`not exists: %s`, c.runNetnsDir)
		}
	} else {
		c.runNetnsDir = `/host/run/netns`
		if exists := util.Exists(c.runNetnsDir); !exists {
			c.runNetnsDir = `/run/netns`
			if exists := util.Exists(c.runNetnsDir); !exists {
				return fmt.Errorf(`not exists: %s`, c.runNetnsDir)
			}
		}
	}

	if len(c.runNetnsDir) == 0 {
		return fmt.Errorf(`invalid run-netns-dir: %s`, c.runNetnsDir)
	}
	return nil
}

func (c *netns) validateNamespaceFlag() error {
	if len(c.namespace) == 0 {
		return fmt.Errorf(`invalid namespace: %s`, c.namespace)
	}
	inode := fmt.Sprintf("%s/%s", c.runNetnsDir, c.namespace)
	if exists := util.Exists(inode); !exists {
		return fmt.Errorf(`not exists: %s`, inode)
	}
	return nil
}

func (c *netns) validateDevFlag() error {
	if len(c.dev) == 0 {
		return fmt.Errorf(`invalid dev: %s`, c.dev)
	}
	return nil
}
