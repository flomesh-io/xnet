package k8s

import (
	"cmp"
	"fmt"
	"net"
	"slices"

	corev1 "k8s.io/api/core/v1"

	"github.com/flomesh-io/xnet/pkg/constants"
	"github.com/flomesh-io/xnet/pkg/k8s/informers"
	"github.com/flomesh-io/xnet/pkg/k8s/kind"
	"github.com/flomesh-io/xnet/pkg/messaging"
	"github.com/flomesh-io/xnet/pkg/xnet/util"
)

// NewKubernetesController returns a new kubernetes.Controller which means to provide access to locally-cached k8s resources
func NewKubernetesController(informerCollection *informers.InformerCollection, msgBroker *messaging.Broker, meshExcludeNamespaces []string) Controller {
	return newClient(informerCollection, msgBroker, meshExcludeNamespaces)
}

func newClient(informerCollection *informers.InformerCollection, msgBroker *messaging.Broker, meshExcludeNamespaces []string) *client {
	// Initialize client object
	c := &client{
		informers:             informerCollection,
		msgBroker:             msgBroker,
		meshExcludeNamespaces: meshExcludeNamespaces,
	}
	c.initSidecarPodMonitor()
	return c
}

// IsMonitoredNamespace returns a boolean indicating if the namespace is among the list of monitored namespaces
func (c *client) IsMonitoredNamespace(namespace string) bool {
	if len(c.meshExcludeNamespaces) > 0 {
		if slices.Contains(c.meshExcludeNamespaces, namespace) {
			return false
		}
	}
	return c.informers.IsMonitoredNamespace(namespace)
}

// ListMonitoredNamespaces returns all namespaces that the mesh is monitoring.
func (c *client) ListMonitoredNamespaces() ([]string, error) {
	var namespaces []string
	for _, ns := range c.informers.List(informers.InformerKeyNamespace) {
		namespace, ok := ns.(*corev1.Namespace)
		if !ok {
			log.Error().Err(errListingNamespaces).Msg("Failed to list monitored namespaces")
			continue
		}
		namespaces = append(namespaces, namespace.Name)
	}
	return namespaces, nil
}

// GetNamespace returns a Namespace resource if found, nil otherwise.
func (c *client) GetNamespace(namespace string) *corev1.Namespace {
	nsIf, exists, err := c.informers.GetByKey(informers.InformerKeyNamespace, namespace)
	if exists && err == nil {
		return nsIf.(*corev1.Namespace)
	}
	return nil
}

func (c *client) IsMonitoredPod(pod string, namespace string) bool {
	podIf, exists, err := c.informers.GetByKey(informers.InformerKeyPod, fmt.Sprintf("%s/%s", namespace, pod))
	if exists && err == nil {
		podIns := podIf.(*corev1.Pod)
		if _, found := podIns.Labels[constants.SidecarUniqueIDLabelName]; found {
			return true
		} else {
			return c.IsMonitoredNamespace(podIns.Namespace)
		}
	}
	return false
}

// ListMonitoredPods returns the pods monitored by the mesh
func (c *client) ListMonitoredPods() []*corev1.Pod {
	var pods []*corev1.Pod
	for _, podInterface := range c.informers.List(informers.InformerKeyPod) {
		podIns := podInterface.(*corev1.Pod)
		if !c.IsMonitoredNamespace(podIns.Namespace) {
			continue
		}
		if _, found := podIns.Labels[constants.SidecarUniqueIDLabelName]; !found {
			continue
		}
		pods = append(pods, podIns)
	}
	return pods
}

func (c *client) GetMonitoredPod(pod, namespace string) *corev1.Pod {
	podIf, exists, err := c.informers.GetByKey(informers.InformerKeyPod, fmt.Sprintf("%s/%s", namespace, pod))
	if exists && err == nil {
		return podIf.(*corev1.Pod)
	}
	return nil
}

// ListSidecarPods returns the gateway pods as sidecar.
func (c *client) ListSidecarPods() []*corev1.Pod {
	var pods []*corev1.Pod

	for _, podInterface := range c.informers.List(informers.InformerKeySidecarPod) {
		podIns := podInterface.(*corev1.Pod)
		if corev1.PodRunning == podIns.Status.Phase {
			pods = append(pods, podIns)
		}
	}

	pods = slices.SortedFunc[*corev1.Pod](slices.Values(pods), func(e1 *corev1.Pod, e2 *corev1.Pod) int {
		n1, _ := util.IPv4ToInt(net.ParseIP(e1.Status.PodIP))
		n2, _ := util.IPv4ToInt(net.ParseIP(e2.Status.PodIP))
		return cmp.Compare(n1, n2)
	})

	return pods
}

// Function to filter K8s meta Objects by FSM's isMonitoredNamespace
func (c *client) shouldObserveSidecarPod(obj interface{}) bool {
	//object, ok := obj.(metav1.Object)
	//if !ok {
	//	return false
	//}
	//return c.IsMonitoredNamespace(object.GetNamespace())
	return true
}

func (c *client) initSidecarPodMonitor() {
	sidecarPodEventTypes := EventTypes{
		Add:    kind.SidecarPodAdded,
		Update: kind.SidecarPodUpdated,
		Delete: kind.SidecarPodDeleted,
	}
	c.informers.AddEventHandler(informers.InformerKeySidecarPod,
		GetEventHandlerFuncs(c.shouldObserveSidecarPod, sidecarPodEventTypes, c.msgBroker))
}
