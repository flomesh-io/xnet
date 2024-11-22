package messaging

import (
	"k8s.io/client-go/util/workqueue"

	"github.com/flomesh-io/xnet/pkg/k8s/events"
)

// GetQueue returns the workqueue instance
func (b *Broker) GetQueue() workqueue.TypedRateLimitingInterface[events.PubSubMessage] {
	return b.queue
}

// processNextItem processes the next item in the workqueue. It returns a boolean
// indicating if the next item in the queue is ready to be processed.
func (b *Broker) processNextItem() bool {
	// Wait for an item to appear in the queue
	item, shutdown := b.queue.Get()
	if shutdown {
		log.Info().Msg("Queue shutdown")
		return false
	}

	// Inform the queue that this 'msg' has been staged for further processing.
	// This is required for safe parallel processing on the queue.
	defer b.queue.Done(item)

	b.processEvent(item)
	b.queue.Forget(item)

	return true
}
