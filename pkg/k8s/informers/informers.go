package informers

import (
	"errors"
	"os"
	"testing"

	"github.com/rs/zerolog/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/flomesh-io/xnet/pkg/constants"
)

// InformerCollectionOption is a function that modifies an informer collection
type InformerCollectionOption func(*InformerCollection)

// NewInformerCollection creates a new InformerCollection
func NewInformerCollection(meshName string, fsmNamespace string, stop <-chan struct{}, opts ...InformerCollectionOption) (*InformerCollection, error) {
	ic := &InformerCollection{
		meshName:     meshName,
		fsmNamespace: fsmNamespace,
		informers:    map[InformerKey]cache.SharedIndexInformer{},
	}

	// Execute all of the given options (e.g. set clients, set custom stores, etc.)
	for _, opt := range opts {
		if opt != nil {
			opt(ic)
		}
	}

	if err := ic.run(stop); err != nil {
		log.Error().Err(err).Msg("Could not start informer collection")
		return nil, err
	}

	return ic, nil
}

// WithKubeClient sets the kubeClient for the InformerCollection
func WithKubeClient(kubeClient kubernetes.Interface) InformerCollectionOption {
	return func(ic *InformerCollection) {
		monitorNamespaceLabel := map[string]string{constants.FSMKubeResourceMonitorAnnotation: ic.meshName}
		monitorNamespaceLabelSelector := fields.SelectorFromSet(monitorNamespaceLabel).String()
		monitorNamespaceOption := informers.WithTweakListOptions(func(opt *metav1.ListOptions) {
			opt.LabelSelector = monitorNamespaceLabelSelector
		})
		nsInformerFactory := informers.NewSharedInformerFactoryWithOptions(kubeClient, DefaultKubeEventResyncInterval, monitorNamespaceOption)
		ic.informers[InformerKeyNamespace] = nsInformerFactory.Core().V1().Namespaces().Informer()

		nodeName := os.Getenv("NODE_NAME")
		if len(nodeName) == 0 {
			log.Fatal().Msg("missing NODE_NAME env")
		}
		nodeSelector := fields.OneTermEqualSelector("spec.nodeName", nodeName).String()

		podNodeOption := informers.WithTweakListOptions(func(opt *metav1.ListOptions) {
			opt.FieldSelector = nodeSelector
		})
		podInformerFactory := informers.NewSharedInformerFactoryWithOptions(kubeClient, DefaultKubeEventResyncInterval, podNodeOption)
		podApi := podInformerFactory.Core().V1()
		ic.informers[InformerKeyPod] = podApi.Pods().Informer()

		sidecarPodLabel := map[string]string{
			constants.SidecarPodLabelName:       constants.SidecarPodLabelValue,
			constants.SidecarNamespaceLabelName: ic.fsmNamespace,
		}
		sidecarPodLabelSelector := fields.SelectorFromSet(sidecarPodLabel).String()

		sidecarPodNodeOption := informers.WithTweakListOptions(func(opt *metav1.ListOptions) {
			opt.LabelSelector = sidecarPodLabelSelector
			opt.FieldSelector = nodeSelector
		})
		sidecarPodInformerFactory := informers.NewSharedInformerFactoryWithOptions(kubeClient, DefaultKubeEventResyncInterval, sidecarPodNodeOption)
		sidecarPodApi := sidecarPodInformerFactory.Core().V1()
		ic.informers[InformerKeySidecarPod] = sidecarPodApi.Pods().Informer()
	}
}

func (ic *InformerCollection) run(stop <-chan struct{}) error {
	log.Info().Msg("InformerCollection started")
	var hasSynced []cache.InformerSynced
	var names []string

	if ic.informers == nil {
		return errInitInformers
	}

	for name, informer := range ic.informers {
		if informer == nil {
			continue
		}

		go informer.Run(stop)
		names = append(names, string(name))
		log.Info().Msgf("Waiting for %s informer cache sync...", name)
		hasSynced = append(hasSynced, informer.HasSynced)
	}

	if !cache.WaitForCacheSync(stop, hasSynced...) {
		return errSyncingCaches
	}

	log.Info().Msgf("Caches for %v synced successfully", names)

	return nil
}

// Add is only exported for the sake of tests and requires a testing.T to ensure it's
// never used in production. This functionality was added for the express purpose of testing
// flexibility since alternatives can often lead to flaky tests and race conditions
// between the time an object is added to a fake clientset and when that object
// is actually added to the informer `cache.Store`
func (ic *InformerCollection) Add(key InformerKey, obj interface{}, t *testing.T) error {
	if t == nil {
		return errors.New("this method should only be used in tests")
	}

	i, ok := ic.informers[key]
	if !ok {
		t.Errorf("tried to add to nil store with key %s", key)
	}

	return i.GetStore().Add(obj)
}

// Update is only exported for the sake of tests and requires a testing.T to ensure it's
// never used in production. This functionality was added for the express purpose of testing
// flexibility since the alternatives can often lead to flaky tests and race conditions
// between the time an object is added to a fake clientset and when that object
// is actually added to the informer `cache.Store`
func (ic *InformerCollection) Update(key InformerKey, obj interface{}, t *testing.T) error {
	if t == nil {
		return errors.New("this method should only be used in tests")
	}

	i, ok := ic.informers[key]
	if !ok {
		t.Errorf("tried to update to nil store with key %s", key)
	}

	return i.GetStore().Update(obj)
}

// AddEventHandler adds an handler to the informer indexed by the given InformerKey
func (ic *InformerCollection) AddEventHandler(informerKey InformerKey, handler cache.ResourceEventHandler) {
	i, ok := ic.informers[informerKey]
	if !ok {
		log.Info().Msgf("attempted to add event handler for nil informer %s", informerKey)
		return
	}

	_, _ = i.AddEventHandler(handler)
}

// GetByKey retrieves an item (based on the given index) from the store of the informer indexed by the given InformerKey
func (ic *InformerCollection) GetByKey(informerKey InformerKey, objectKey string) (interface{}, bool, error) {
	informer, ok := ic.informers[informerKey]
	if !ok {
		// keithmattix: This is the silent failure option, but perhaps we want to return an error?
		return nil, false, nil
	}

	return informer.GetStore().GetByKey(objectKey)
}

// List returns the contents of the store of the informer indexed by the given InformerKey
func (ic *InformerCollection) List(informerKey InformerKey) []interface{} {
	informer, ok := ic.informers[informerKey]
	if !ok {
		// keithmattix: This is the silent failure option, but perhaps we want to return an error?
		return nil
	}

	return informer.GetStore().List()
}

// IsMonitoredNamespace returns a boolean indicating if the namespace is among the list of monitored namespaces
func (ic *InformerCollection) IsMonitoredNamespace(namespace string) bool {
	_, exists, _ := ic.informers[InformerKeyNamespace].GetStore().GetByKey(namespace)
	return exists
}

// GetListers returns the listers for the informers
//func (ic *InformerCollection) GetListers() *Lister {
//	return ic.listers
//}

//gocyclo:ignore
//func (ic *InformerCollection) GetGatewayResourcesFromCache(resourceType ResourceType, shouldSort bool) []client.Object {
//	resources := make([]client.Object, 0)
//
//	switch resourceType {
//	case GatewayClassesResourceType:
//		classes, err := ic.listers.GatewayClass.List(selectAll)
//		if err != nil {
//			log.Error().Msgf("Failed to get GatewayClasses: %s", err)
//			return resources
//		}
//		resources = setGroupVersionKind(classes, constants.GatewayClassGVK)
//	case GatewaysResourceType:
//		gateways, err := ic.listers.Gateway.List(selectAll)
//		if err != nil {
//			log.Error().Msgf("Failed to get Gateways: %s", err)
//			return resources
//		}
//		resources = setGroupVersionKind(gateways, constants.GatewayGVK)
//	case HTTPRoutesResourceType:
//		routes, err := ic.listers.HTTPRoute.List(selectAll)
//		if err != nil {
//			log.Error().Msgf("Failed to get HTTPRoutes: %s", err)
//			return resources
//		}
//		resources = setGroupVersionKind(routes, constants.HTTPRouteGVK)
//	case GRPCRoutesResourceType:
//		routes, err := ic.listers.GRPCRoute.List(selectAll)
//		if err != nil {
//			log.Error().Msgf("Failed to get GRPCRouts: %s", err)
//			return resources
//		}
//		resources = setGroupVersionKind(routes, constants.GRPCRouteGVK)
//	case TLSRoutesResourceType:
//		routes, err := ic.listers.TLSRoute.List(selectAll)
//		if err != nil {
//			log.Error().Msgf("Failed to get TLSRoutes: %s", err)
//			return resources
//		}
//		resources = setGroupVersionKind(routes, constants.TLSRouteGVK)
//	case TCPRoutesResourceType:
//		routes, err := ic.listers.TCPRoute.List(selectAll)
//		if err != nil {
//			log.Error().Msgf("Failed to get TCPRoutes: %s", err)
//			return resources
//		}
//		resources = setGroupVersionKind(routes, constants.TCPRouteGVK)
//	case UDPRoutesResourceType:
//		routes, err := ic.listers.UDPRoute.List(selectAll)
//		if err != nil {
//			log.Error().Msgf("Failed to get UDPRoutes: %s", err)
//			return resources
//		}
//		resources = setGroupVersionKind(routes, constants.UDPRouteGVK)
//	case ReferenceGrantResourceType:
//		grants, err := ic.listers.ReferenceGrant.List(selectAll)
//		if err != nil {
//			log.Error().Msgf("Failed to get ReferenceGrants: %s", err)
//			return resources
//		}
//		resources = setGroupVersionKind(grants, constants.ReferenceGrantGVK)
//	case UpstreamTLSPoliciesResourceType:
//		policies, err := ic.listers.UpstreamTLSPolicy.List(selectAll)
//		if err != nil {
//			log.Error().Msgf("Failed to get UpstreamTLSPolicies: %s", err)
//			return resources
//		}
//		resources = setGroupVersionKind(policies, constants.UpstreamTLSPolicyGVK)
//	case RateLimitPoliciesResourceType:
//		policies, err := ic.listers.RateLimitPolicy.List(selectAll)
//		if err != nil {
//			log.Error().Msgf("Failed to get RateLimitPolicies: %s", err)
//			return resources
//		}
//		resources = setGroupVersionKind(policies, constants.RateLimitPolicyGVK)
//	case AccessControlPoliciesResourceType:
//		policies, err := ic.listers.AccessControlPolicy.List(selectAll)
//		if err != nil {
//			log.Error().Msgf("Failed to get AccessControlPolicies: %s", err)
//			return resources
//		}
//		resources = setGroupVersionKind(policies, constants.AccessControlPolicyGVK)
//	case FaultInjectionPoliciesResourceType:
//		policies, err := ic.listers.FaultInjectionPolicy.List(selectAll)
//		if err != nil {
//			log.Error().Msgf("Failed to get FaultInjectionPolicies: %s", err)
//			return resources
//		}
//		resources = setGroupVersionKind(policies, constants.FaultInjectionPolicyGVK)
//	case SessionStickyPoliciesResourceType:
//		policies, err := ic.listers.SessionStickyPolicy.List(selectAll)
//		if err != nil {
//			log.Error().Msgf("Failed to get SessionStickyPolicies: %s", err)
//			return resources
//		}
//		resources = setGroupVersionKind(policies, constants.SessionStickyPolicyGVK)
//	case LoadBalancerPoliciesResourceType:
//		policies, err := ic.listers.LoadBalancerPolicy.List(selectAll)
//		if err != nil {
//			log.Error().Msgf("Failed to get LoadBalancerPolicies: %s", err)
//			return resources
//		}
//		resources = setGroupVersionKind(policies, constants.LoadBalancerPolicyGVK)
//	case CircuitBreakingPoliciesResourceType:
//		policies, err := ic.listers.CircuitBreakingPolicy.List(selectAll)
//		if err != nil {
//			log.Error().Msgf("Failed to get CircuitBreakingPolicies: %s", err)
//			return resources
//		}
//		resources = setGroupVersionKind(policies, constants.CircuitBreakingPolicyGVK)
//	case HealthCheckPoliciesResourceType:
//		policies, err := ic.listers.HealthCheckPolicy.List(selectAll)
//		if err != nil {
//			log.Error().Msgf("Failed to get HealthCheckPolicies: %s", err)
//			return resources
//		}
//		resources = setGroupVersionKind(policies, constants.HealthCheckPolicyGVK)
//	case RetryPoliciesResourceType:
//		policies, err := ic.listers.RetryPolicy.List(selectAll)
//		if err != nil {
//			log.Error().Msgf("Failed to get RetryPolicies: %s", err)
//			return resources
//		}
//		resources = setGroupVersionKind(policies, constants.RetryPolicyGVK)
//	default:
//		log.Error().Msgf("Unknown resource type: %s", resourceType)
//		return nil
//	}
//
//	if shouldSort {
//		sort.Slice(resources, func(i, j int) bool {
//			if resources[i].GetCreationTimestamp().Time.Equal(resources[j].GetCreationTimestamp().Time) {
//				return client.ObjectKeyFromObject(resources[i]).String() < client.ObjectKeyFromObject(resources[j]).String()
//			}
//
//			return resources[i].GetCreationTimestamp().Time.Before(resources[j].GetCreationTimestamp().Time)
//		})
//	}
//
//	return resources
//}
//
//func setGroupVersionKind[T GatewayAPIResource](objects []T, gvk schema.GroupVersionKind) []client.Object {
//	resources := make([]client.Object, 0)
//
//	for _, obj := range objects {
//		obj := client.Object(obj)
//		obj.GetObjectKind().SetGroupVersionKind(gvk)
//		resources = append(resources, obj)
//	}
//
//	return resources
//}
