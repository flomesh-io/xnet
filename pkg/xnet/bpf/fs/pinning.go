package fs

import (
	"path"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf"
)

func GetPinningDir() string {
	return path.Join(BPFFSPath, bpf.FSM_PROG_NAME)
}

func GetPinningFile(objName string) string {
	return path.Join(BPFFSPath, bpf.FSM_PROG_NAME, objName)
}
