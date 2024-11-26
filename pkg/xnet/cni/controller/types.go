package controller

import "github.com/flomesh-io/xnet/pkg/logger"

var (
	log = logger.New("fsm-xnet-ctrl")
)

const (
	bridgeDev = `cni0`

	sidecarAclId   = uint16('g'<<8 | 'w')
	sidecarAclFlag = uint8('f')

	bridgeAclId   = uint16('b'<<8 | 'r')
	bridgeAclFlag = uint8('c')
)

// Server CNI Server.
type Server interface {
	Start() error
	Stop()
}
