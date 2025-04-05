package fs

import (
	"fmt"
	"syscall"

	"github.com/flomesh-io/xnet/pkg/xnet/util"
)

// IsMountedAt checks if the BPF fs is mounted already in the custom location
func IsMountedAt(mountpoint string) (bool, error) {
	var data syscall.Statfs_t
	if err := syscall.Statfs(mountpoint, &data); err != nil {
		return false, fmt.Errorf("cannot statfs %q: %v", mountpoint, err)
	}
	return data.Type == uint32(fsMagic), nil
}

// IsMounted checks if the BPF fs is mounted already in the default location
func IsMounted() (bool, error) {
	return IsMountedAt(BPFFSPath)
}

// MountAt mounts the BPF fs in the custom location (if not already mounted)
func MountAt(mountpoint string) error {
	mounted, err := IsMountedAt(mountpoint)
	if err != nil {
		return err
	}
	if mounted {
		return nil
	}
	if err = util.Mount(mountpoint, mountpoint, "bpf", 0, ""); err != nil {
		return fmt.Errorf("error mounting %q: %v", mountpoint, err)
	}
	return nil
}

// Mount the BPF fs in the default location (if not already mounted)
func Mount() error {
	return MountAt(BPFFSPath)
}
