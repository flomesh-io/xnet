package messaging

import (
	"time"

	"github.com/cskr/pubsub"
	"golang.org/x/time/rate"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"

	"github.com/flomesh-io/xnet/pkg/k8s/events"
	"github.com/flomesh-io/xnet/pkg/k8s/kind"
)

const (
	// sidecarUpdateSlidingWindow is the sliding window duration used to batch sidecar update events
	sidecarUpdateSlidingWindow = 2 * time.Second

	// sidecarUpdateMaxWindow is the max window duration used to batch sidecar update events, and is
	// the max amount of time a sidecar update event can be held for batching before being dispatched.
	sidecarUpdateMaxWindow = 4 * time.Second
)

// NewBroker returns a new message broker instance and starts the internal goroutine
// to process events added to the workqueue.
func NewBroker(stopCh <-chan struct{}) *Broker {
	rateLimiter := workqueue.NewTypedMaxOfRateLimiter[events.PubSubMessage](
		workqueue.NewTypedItemExponentialFailureRateLimiter[events.PubSubMessage](5*time.Millisecond, 1000*time.Second),
		// 1024*5 qps, 1024*8 bucket size.  This is only for retry speed and its only the overall factor (not per item)
		&workqueue.TypedBucketRateLimiter[events.PubSubMessage]{Limiter: rate.NewLimiter(rate.Limit(1024*8), 1024*9)},
	)
	b := &Broker{
		queue:               workqueue.NewTypedRateLimitingQueue[events.PubSubMessage](rateLimiter),
		sidecarUpdatePubSub: pubsub.New(1024 * 10),
		sidecarUpdateCh:     make(chan sidecarUpdateEvent),
		kubeEventPubSub:     pubsub.New(1024 * 10),
	}

	go b.runWorkqueueProcessor(stopCh)
	go b.runSidecarUpdateDispatcher(stopCh)

	return b
}

// GetSidecarUpdatePubSub returns the PubSub instance corresponding to sidecar update events
func (b *Broker) GetSidecarUpdatePubSub() *pubsub.PubSub {
	return b.sidecarUpdatePubSub
}

// runWorkqueueProcessor starts a goroutine to process events from the workqueue until
// signalled to stop on the given channel.
func (b *Broker) runWorkqueueProcessor(stopCh <-chan struct{}) {
	// Start the goroutine workqueue to process kubernetes events
	// The continuous processing of items in the workqueue will run
	// until signalled to stop.
	// The 'wait.Until' helper is used here to ensure the processing
	// of items in the workqueue continues until signalled to stop, even
	// if 'processNextItems()' returns false.
	go wait.Until(
		func() {
			for b.processNextItem() {
			}
		},
		time.Second,
		stopCh,
	)
}

// runSidecarUpdateDispatcher runs the dispatcher responsible for batching
// sidecar update events received in close proximity.
// It batches sidecar update events with the use of 2 timers:
// 1. Sliding window timer that resets when a sidecar update event is received
// 2. Max window timer that caps the max duration a sliding window can be reset to
// When either of the above timers expire, the sidecar update event is published
// on the dedicated pub-sub instance.
func (b *Broker) runSidecarUpdateDispatcher(stopCh <-chan struct{}) {
	// batchTimer and maxTimer are updated by the dispatcher routine
	// when events are processed and timeouts expire. They are initialized
	// with a large timeout (a decade) so they don't time out till an event
	// is received.
	noTimeout := 87600 * time.Hour // A decade
	slidingTimer := time.NewTimer(noTimeout)
	maxTimer := time.NewTimer(noTimeout)

	// dispatchPending indicates whether a sidecar update event is pending
	// from being published on the pub-sub. A sidecar update event will
	// be held for 'sidecarUpdateSlidingWindow' duration to be able to
	// coalesce multiple sidecar update events within that duration, before
	// it is dispatched on the pub-sub. The 'sidecarUpdateSlidingWindow' duration
	// is a sliding window, which means each event received within a window
	// slides the window further ahead in time, up to a max of 'sidecarUpdateMaxWindow'.
	//
	// This mechanism is necessary to avoid triggering sidecar update pub-sub events in
	// a hot loop, which would otherwise result in CPU spikes on the controller.
	// We want to coalesce as many sidecar update events within the 'sidecarUpdateMaxWindow'
	// duration.
	dispatchPending := false
	batchCount := 0 // number of proxy update events batched per dispatch

	var event sidecarUpdateEvent
	for {
		select {
		case e, ok := <-b.sidecarUpdateCh:
			if !ok {
				log.Warn().Msgf("Sidecar update event chan closed, exiting dispatcher")
				return
			}
			event = e

			if !dispatchPending {
				// No sidecar update events are pending send on the pub-sub.
				// Reset the dispatch timers. The events will be dispatched
				// when either of the timers expire.
				if !slidingTimer.Stop() {
					<-slidingTimer.C
				}
				slidingTimer.Reset(sidecarUpdateSlidingWindow)
				if !maxTimer.Stop() {
					<-maxTimer.C
				}
				maxTimer.Reset(sidecarUpdateMaxWindow)
				dispatchPending = true
				batchCount++
				log.Trace().Msgf("Pending dispatch of msg kind %s", event.msg.Kind)
			} else {
				// A sidecar update event is pending dispatch. Update the sliding window.
				if !slidingTimer.Stop() {
					<-slidingTimer.C
				}
				slidingTimer.Reset(sidecarUpdateSlidingWindow)
				batchCount++
				log.Trace().Msgf("Reset sliding window for msg kind %s", event.msg.Kind)
			}

		case <-slidingTimer.C:
			slidingTimer.Reset(noTimeout) // 'slidingTimer' drained in this case statement
			// Stop and drain 'maxTimer' before Reset()
			if !maxTimer.Stop() {
				// Drain channel. Refer to Reset() doc for more info.
				<-maxTimer.C
			}
			maxTimer.Reset(noTimeout)
			b.sidecarUpdatePubSub.Pub(event.msg, event.topic)
			log.Trace().Msgf("Sliding window expired, msg kind %s, batch size %d", event.msg.Kind, batchCount)
			dispatchPending = false
			batchCount = 0

		case <-maxTimer.C:
			maxTimer.Reset(noTimeout) // 'maxTimer' drained in this case statement
			// Stop and drain 'slidingTimer' before Reset()
			if !slidingTimer.Stop() {
				// Drain channel. Refer to Reset() doc for more info.
				<-slidingTimer.C
			}
			slidingTimer.Reset(noTimeout)
			b.sidecarUpdatePubSub.Pub(event.msg, event.topic)
			log.Trace().Msgf("Max window expired, msg kind %s, batch size %d", event.msg.Kind, batchCount)
			dispatchPending = false
			batchCount = 0

		case <-stopCh:
			log.Info().Msg("Sidecar update dispatcher received stop signal, exiting")
			return
		}
	}
}

// processEvent processes an event dispatched from the workqueue.
// It does the following:
// 1. If the event must update a sidecar, it publishes a pod update message
// 2. Processes other internal control plane events
// 3. Updates metrics associated with the event
func (b *Broker) processEvent(msg events.PubSubMessage) {
	log.Trace().Msgf("Processing msg kind: %s", msg.Kind)
	// Update pods if applicable
	if event := getSidecarUpdateEvent(msg); event != nil {
		log.Trace().Msgf("Msg kind %s will update sidecars", msg.Kind)
		if event.topic != kind.SidecarUpdate.String() {
			// This is not a broadcast event, so it cannot be coalesced with
			// other events as the event is specific to one or more sidecars.
			b.sidecarUpdatePubSub.Pub(event.msg, event.topic)
		} else {
			// Pass the broadcast event to the dispatcher routine, that coalesces
			// multiple broadcasts received in close proximity.
			b.sidecarUpdateCh <- *event
		}
	}

	// Publish event to other interested clients, e.g. log level changes, debug server on/off etc.
	b.kubeEventPubSub.Pub(msg, msg.Kind.String())
}

// Unsub unsubscribes the given channel from the PubSub instance
func (b *Broker) Unsub(pubSub *pubsub.PubSub, ch chan interface{}) {
	// Unsubscription should be performed from a different goroutine and
	// existing messages on the subscribed channel must be drained as noted
	// in https://github.com/cskr/pubsub/blob/v1.0.2/pubsub.go#L95.
	go pubSub.Unsub(ch)
	for range ch {
		// Drain channel until 'Unsub' results in a close on the subscribed channel
	}
}

// getSidecarUpdateEvent returns a sidecarUpdateEvent type
func getSidecarUpdateEvent(msg events.PubSubMessage) *sidecarUpdateEvent {
	switch msg.Kind {
	case kind.SidecarUpdate, kind.SidecarPodAdded, kind.SidecarPodDeleted, kind.SidecarPodUpdated:
		return &sidecarUpdateEvent{
			msg:   msg,
			topic: kind.SidecarUpdate.String(),
		}

	default:
		return nil
	}
}
