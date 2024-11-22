package load

import (
	"github.com/flomesh-io/xnet/pkg/logger"
	"github.com/flomesh-io/xnet/pkg/xnet/util"
)

var (
	searchPaths = []string{
		`/app/.fsm/.xnet.kern.o`,
		`/app/.fsm/xnet.kern.o`,
		`.fsm/.xnet.kern.o`,
		`.fsm/xnet.kern.o`,
		`bin/.xnet.kern.o`,
		`bin/xnet.kern.o`,
		`.xnet.kern.o`,
		`xnet.kern.o`,
	}
	bpfProgPath = ``
	log         = logger.New("fsm-xnet-bpf-load")
)

func init() {
	for _, searchPath := range searchPaths {
		if exists := util.Exists(searchPath); exists {
			bpfProgPath = searchPath
			return
		}
	}
	log.Fatal().Msgf("not found bpf prog: %s", bpfProgPath)
}
