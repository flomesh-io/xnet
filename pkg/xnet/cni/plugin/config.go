package plugin

import (
	"fmt"
	"os"

	"github.com/flomesh-io/xnet/pkg/xnet/cni"
	"github.com/flomesh-io/xnet/pkg/xnet/volume"
)

func SetLogFile(file string) {
	// #nosec G304
	logfile, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err == nil {
		log = log.Output(logfile)
	}
}

func GetUnixSock() string {
	return cni.GetCniSock(volume.SysRun.HostPath)
}

func GetConfig() string {
	return fmt.Sprintf(`%s.conf`, GetUnixSock())
}

type Config struct {
	LogLevel string `json:"LogLevel,omitempty"`
	LogFile  string `json:"LogFile,omitempty"`
}
