package cli

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/cni"
	"github.com/flomesh-io/xnet/pkg/xnet/util"
)

const waitDescription = ``
const waitExample = ``

type waitCmd struct {
	unixSock string
}

func NewWaitCmd() *cobra.Command {
	wait := &waitCmd{}

	cmd := &cobra.Command{
		Use:     "wait",
		Short:   "wait",
		Long:    waitDescription,
		Aliases: []string{"w"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return wait.run()
		},
		Example: waitExample,
	}

	//add flags
	f := cmd.Flags()
	f.StringVar(&wait.unixSock, "unix-sock", "/host/run/.xnet.sock", "--unix-sock=unix.sock")

	return cmd
}

func (a *waitCmd) run() error {
	for {
		if util.Exists(a.unixSock) {
			httpc := http.Client{
				Transport: &http.Transport{
					DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
						return net.Dial("unix", a.unixSock)
					},
				},
			}
			if r, err := httpc.Get("http://" + cni.PluginName + cni.VersionURI); err == nil {
				if r.StatusCode == http.StatusOK {
					break
				}
			}
		}
		time.Sleep(time.Second * 2)
	}
	return nil
}
