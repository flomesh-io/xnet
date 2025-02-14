package volume

type HostMount struct {
	HostPath  string
	MountPath string
}

var (
	Sysfs = HostMount{
		HostPath:  "/opt",
		MountPath: "/host/sys/fs",
	}

	SysProc = HostMount{
		HostPath:  "/proc",
		MountPath: "/host/proc",
	}

	SysRun = HostMount{
		HostPath:  "/var/run",
		MountPath: "/host/run",
	}

	Netns = HostMount{
		HostPath:  "/var/run/netns",
		MountPath: "/host/run/netns",
	}

	CniBin = HostMount{
		HostPath:  "/bin",
		MountPath: "/host/cni/bin",
	}

	CniNetd = HostMount{
		//HostPath:  "/etc/cni/net.d", //k8s
		HostPath:  "/var/lib/rancher/k3s/agent/etc/cni/net.d", //k3s
		MountPath: "/host/cni/net.d",
	}
)
