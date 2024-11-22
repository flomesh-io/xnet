package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"

	"github.com/flomesh-io/xnet/pkg/xnet/cni"
	"github.com/flomesh-io/xnet/pkg/xnet/util"
	"github.com/flomesh-io/xnet/pkg/xnet/volume"
)

// K8sArgs is the valid CNI_ARGS used for Kubernetes
// The field names need to match exact keys in kubelet args for unmarshalling
type K8sArgs struct {
	types.CommonArgs
	IP                         net.IP
	K8S_POD_NAME               types.UnmarshallableString // nolint: revive, stylecheck
	K8S_POD_NAMESPACE          types.UnmarshallableString // nolint: revive, stylecheck
	K8S_POD_INFRA_CONTAINER_ID types.UnmarshallableString // nolint: revive, stylecheck
}

// CmdAdd is the implementation of the cmdAdd interface of CNI plugin
func CmdAdd(args *skel.CmdArgs) error {
	conf, err := parsePodNetConf(args.StdinData)
	if err != nil {
		log.Error().Msgf("%s cmdAdd failed to parse config %v %v", cni.PluginName, string(args.StdinData), err)
	} else {
		k8sArgs := K8sArgs{}
		if err = types.LoadArgs(args.Args, &k8sArgs); err != nil {
			log.Error().Msgf("%s cmdAdd failed to load args %v %v", cni.PluginName, string(args.StdinData), err)
		} else if util.Exists(GetUnixSock()) {
			httpc := http.Client{
				Transport: &http.Transport{
					DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
						return net.Dial("unix", GetUnixSock())
					},
				},
			}
			bs, _ := json.Marshal(args)
			body := bytes.NewReader(bs)
			log.Info().Msgf("CNICreatePod %s/%s", k8sArgs.K8S_POD_NAMESPACE, k8sArgs.K8S_POD_NAME)
			if _, err = httpc.Post("http://"+cni.PluginName+cni.CreatePodURI, "application/json", body); err != nil {
				log.Error().Msgf("%s cmdAdd failed to post args %v %v", cni.PluginName, string(args.StdinData), err)
			}
		}
	}

	var result *cniv1.Result
	if conf.PrevResult == nil {
		result = &cniv1.Result{
			CNIVersion: cniv1.ImplementedSpecVersion,
		}
	} else {
		// Pass through the result for the next plugin
		result = conf.PrevResult
	}
	return types.PrintResult(result, conf.CNIVersion) //nolint:typecheck
}

// CmdCheck is the implementation of the cmdCheck interface of CNI plugin
func CmdCheck(*skel.CmdArgs) (err error) {
	return nil
}

// CmdDelete is the implementation of the cmdDelete interface of CNI plugin
func CmdDelete(args *skel.CmdArgs) error {
	k8sArgs := K8sArgs{}
	if err := types.LoadArgs(args.Args, &k8sArgs); err != nil {
		log.Error().Msgf("%s cmdAdd failed to load args %v %v", cni.PluginName, string(args.StdinData), err)
	} else if util.Exists(cni.GetCniSock(volume.SysRun.HostPath)) {
		httpc := http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", cni.GetCniSock(volume.SysRun.HostPath))
				},
			},
		}
		bs, _ := json.Marshal(args)
		body := bytes.NewReader(bs)
		log.Info().Msgf("CNIDeletePod %s/%s", k8sArgs.K8S_POD_NAMESPACE, k8sArgs.K8S_POD_NAME)
		if _, err := httpc.Post("http://"+cni.PluginName+cni.DeletePodURI, "application/json", body); err != nil {
			log.Error().Msgf("%s cmdDelete failed to parse config %v %v", cni.PluginName, string(args.StdinData), err)
		}
	}
	return nil
}
