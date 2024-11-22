// Package messaging implements the messaging infrastructure between different
// components within the control plane.
package messaging

import (
	"github.com/cskr/pubsub"
	"k8s.io/client-go/util/workqueue"

	"github.com/flomesh-io/xnet/pkg/k8s/events"
	"github.com/flomesh-io/xnet/pkg/logger"
)

var (
	log = logger.New("message-broker")
)

// Broker implements the message broker functionality
type Broker struct {
	queue               workqueue.TypedRateLimitingInterface[events.PubSubMessage]
	sidecarUpdatePubSub *pubsub.PubSub
	sidecarUpdateCh     chan sidecarUpdateEvent
	kubeEventPubSub     *pubsub.PubSub
}

// sidecarUpdateEvent specifies the PubSubMessage and topic for an event that
// results in a proxy config update
type sidecarUpdateEvent struct {
	msg   events.PubSubMessage
	topic string
}
