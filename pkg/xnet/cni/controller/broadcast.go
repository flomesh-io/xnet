package controller

import (
	"time"

	"github.com/flomesh-io/xnet/pkg/k8s/kind"
)

// Routine which fulfills listening to proxy broadcasts
func (s *server) broadcastListener() {
	sidecarUpdatePubSub := s.msgBroker.GetSidecarUpdatePubSub()
	sidecarUpdateChan := sidecarUpdatePubSub.Sub(kind.SidecarUpdate.String())
	defer s.msgBroker.Unsub(sidecarUpdatePubSub, sidecarUpdateChan)

	syncPeriod := time.Second * 4
	slidingTimer := time.NewTimer(syncPeriod)
	defer slidingTimer.Stop()

	for {
		select {
		case <-s.stop:
			return
		case <-sidecarUpdateChan:
			slidingTimer.Reset(syncPeriod)
		case <-slidingTimer.C:
			s.configMeshPolicies()
		}
	}
}
