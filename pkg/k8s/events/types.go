package events

import (
	"github.com/flomesh-io/xnet/pkg/k8s/kind"
)

// PubSubMessage represents a common messages abstraction to pass through the PubSub interface
type PubSubMessage struct {
	Kind   kind.Kind
	OldObj interface{}
	NewObj interface{}
}
