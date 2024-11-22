package k8s

import (
	"k8s.io/client-go/tools/cache"

	"github.com/flomesh-io/xnet/pkg/k8s/events"
	"github.com/flomesh-io/xnet/pkg/k8s/kind"
	"github.com/flomesh-io/xnet/pkg/messaging"
)

// observeFilter returns true for YES observe and false for NO do not pay attention to this
// This filter could be added optionally by anything using GetEventHandlerFuncs()
type observeFilter func(obj interface{}) bool

// EventTypes is a struct helping pass the correct types to GetEventHandlerFuncs()
type EventTypes struct {
	Add    kind.Kind
	Update kind.Kind
	Delete kind.Kind
}

// GetEventHandlerFuncs returns the ResourceEventHandlerFuncs object used to receive events when a k8s
// object is added/updated/deleted.
func GetEventHandlerFuncs(shouldObserve observeFilter, eventTypes EventTypes, msgBroker *messaging.Broker) cache.ResourceEventHandlerFuncs {
	if shouldObserve == nil {
		shouldObserve = func(obj interface{}) bool { return true }
	}

	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if !shouldObserve(obj) {
				return
			}
			msgBroker.GetQueue().AddRateLimited(events.PubSubMessage{
				Kind:   eventTypes.Add,
				NewObj: obj,
				OldObj: nil,
			})
		},

		UpdateFunc: func(oldObj, newObj interface{}) {
			if !shouldObserve(newObj) {
				return
			}
			msgBroker.GetQueue().AddRateLimited(events.PubSubMessage{
				Kind:   eventTypes.Update,
				NewObj: newObj,
				OldObj: oldObj,
			})
		},

		DeleteFunc: func(obj interface{}) {
			if !shouldObserve(obj) {
				return
			}
			msgBroker.GetQueue().AddRateLimited(events.PubSubMessage{
				Kind:   eventTypes.Delete,
				NewObj: nil,
				OldObj: obj,
			})
		},
	}
}
