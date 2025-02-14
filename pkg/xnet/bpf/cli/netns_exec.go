package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/utils/exec"

	"github.com/flomesh-io/xnet/pkg/xnet/ns"
)

const netnsExecDescription = ``
const netnsExecExample = ``

type netnsExecCmd struct {
	netns
}

func newNetnsExec() *cobra.Command {
	netnsExec := &netnsExecCmd{}

	cmd := &cobra.Command{
		Use:     "exec",
		Short:   "exec",
		Long:    netnsExecDescription,
		Aliases: []string{"e", "ex", "exe"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return netnsExec.run(args[0])
		},
		Example: netnsExecExample,
	}

	//add flags
	f := cmd.Flags()
	netnsExec.addRunNetnsDirFlag(f)
	return cmd
}

func (a *netnsExecCmd) run(cmd string) error {
	if err := a.validateRunNetnsDirFlag(); err != nil {
		return err
	}
	rd, err := os.ReadDir(a.runNetnsDir)
	if err != nil {
		return err
	}
	for _, fi := range rd {
		nsName, inode := ns.GetInode(fi, a.runNetnsDir)
		netNS, nsErr := ns.GetNS(inode)
		if nsErr != nil {
			continue
		}
		_ = netNS.Do(func(_ ns.NetNS) error {
			fmt.Printf("netns: %s exec: %s\n", nsName, cmd)
			args := strings.Split(cmd, " ")
			ex := exec.New()
			command := ex.Command(args[0], args[0:]...)
			out, exeErr := command.CombinedOutput()
			if exeErr != nil {
				return exeErr
			}
			fmt.Println(string(out))
			return nil
		})
	}
	return nil
}
