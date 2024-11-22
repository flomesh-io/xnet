package controller

import "github.com/flomesh-io/xnet/pkg/logger"

var (
	log = logger.New("fsm-xnet-ctrl")
)

const (
	sidecarAclId   = uint16('g'<<8 | 'w')
	sidecarAclFlag = uint8('f')
)

// Server CNI Server.
type Server interface {
	Start() error
	Stop()
}
