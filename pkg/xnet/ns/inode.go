package ns

import (
	"fmt"
	"os"
)

func GetInode(netns os.DirEntry, netnsDir string) (string, string) {
	nsName := netns.Name()
	inode := fmt.Sprintf(`%s/%s`, netnsDir, netns.Name())
	if netns.IsDir() {
		inode = fmt.Sprintf(`%s/%s/ns/net`, netnsDir, netns.Name())
		nsName = fmt.Sprintf(`%s/ns/net`, netns.Name())
	}
	return nsName, inode
}
