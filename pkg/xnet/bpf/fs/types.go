package fs

import (
	"os"
	"path"

	"github.com/cilium/ebpf/rlimit"

	"github.com/flomesh-io/xnet/pkg/logger"
	"github.com/flomesh-io/xnet/pkg/xnet/util"
	"github.com/flomesh-io/xnet/pkg/xnet/volume"
)

const (
	fsMagic = 0xCAFE4A11
)

var (
	BPFFSPath = `/sys/fs/bpf`

	log = logger.New("fsm-xnet-bpf-fs")
)

func init() {
	if exists := util.Exists(volume.Sysfs.MountPath); exists {
		BPFFSPath = path.Join(volume.Sysfs.MountPath, `bpf`)
	}
	if exists := util.Exists(BPFFSPath); !exists {
		if err := os.MkdirAll(BPFFSPath, 0750); err != nil {
			log.Fatal().Msg(err.Error())
		}
	}
	if err := Mount(); err != nil {
		log.Fatal().Err(err).Msgf(`failed to Mount bpf fs at:%s`, BPFFSPath)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Error().Msgf("remove mem lock error: %v", err)
	}
}
