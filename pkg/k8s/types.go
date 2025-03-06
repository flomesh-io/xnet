package k8s

import (
	corev1 "k8s.io/api/core/v1"

	"github.com/flomesh-io/xnet/pkg/k8s/informers"
	"github.com/flomesh-io/xnet/pkg/logger"
	"github.com/flomesh-io/xnet/pkg/messaging"
)

var (
	log = logger.New("kube-controller")
)

// client is the type used to represent the k8s client for the native k8s resources
type client struct {
	informers             *informers.InformerCollection
	msgBroker             *messaging.Broker
	meshExcludeNamespaces []string
}

// Controller is the controller interface for K8s services
type Controller interface {

	// IsMonitoredNamespace returns whether a namespace with the given name is being monitored
	// by the mesh
	IsMonitoredNamespace(namespace string) bool

	// ListMonitoredNamespaces returns the namespaces monitored by the mesh
	ListMonitoredNamespaces() ([]string, error)

	// GetNamespace returns k8s namespace present in cache
	GetNamespace(namespace string) *corev1.Namespace

	IsMonitoredPod(pod string, namespace string) bool

	// ListMonitoredPods returns the pods monitored by the mesh
	ListMonitoredPods() []*corev1.Pod

	// GetMonitoredPod returns k8s pod present in cache
	GetMonitoredPod(pod string, namespace string) *corev1.Pod

	// ListSidecarPods returns the gateway pods as sidecar.
	ListSidecarPods() []*corev1.Pod
}
