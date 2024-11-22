package deliver

import (
	"fmt"

	"github.com/flomesh-io/xnet/pkg/logger"
	"github.com/flomesh-io/xnet/pkg/xnet/cni"
)

const (
	pluginListSuffix = "list"
)

var (
	log = logger.New("fsm-xnet-cni-plugin")

	kubeConfigFileName = fmt.Sprintf(`ZZZ-%s-kubeconfig`, cni.PluginName)

	cniConfigTemplate = fmt.Sprintf(`# KubeConfig file for CNI plugin.
apiVersion: v1
kind: Config
clusters:
- name: local
  cluster:
    server: {{.KubernetesServiceProtocol}}://[{{.KubernetesServiceHost}}]:{{.KubernetesServicePort}}
    {{.TLSConfig}}
users:
- name: %s
  user:
    token: "{{.ServiceAccountToken}}"
contexts:
- name: %s-context
  context:
    cluster: local
    user: %s
current-context: %s-context
`,
		cni.PluginName,
		cni.PluginName,
		cni.PluginName,
		cni.PluginName)
)
