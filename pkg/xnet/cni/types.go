package cni

import "path"

const (
	unixSock = ".xnet.sock"

	PluginName = "xcni"

	PluginLoopBack = "loopback"

	// CreatePodURI is the route for cni plugin for creating pod
	CreatePodURI = "/v1/cni/create-pod"
	// DeletePodURI is the route for cni plugin for deleting pod
	DeletePodURI = "/v1/cni/delete-pod"
)

func GetCniSock(runDir string) string {
	return path.Join(runDir, unixSock)
}
