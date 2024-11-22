package util

import "golang.org/x/sys/unix"

func Uptime() uint64 {
	sysinfo := &unix.Sysinfo_t{}
	if err := unix.Sysinfo(sysinfo); err != nil {
		return 0
	}
	return uint64(sysinfo.Uptime)
}
