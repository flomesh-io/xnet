package kind

// Kind is used to record the kind of announcement
type Kind string

func (at Kind) String() string {
	return string(at)
}

const (
	// SidecarUpdate is the event kind used to trigger an update to subscribed sidecars
	SidecarUpdate Kind = "sidecar-update"

	// SidecarPodAdded is the type of announcement emitted when we observe an addition of a sidecar Pod
	SidecarPodAdded Kind = "sidecar-pod-added"

	// SidecarPodDeleted the type of announcement emitted when we observe the deletion of a sidecar Pod
	SidecarPodDeleted Kind = "sidecar-pod-deleted"

	// SidecarPodUpdated is the type of announcement emitted when we observe an update to a sidecar Pod
	SidecarPodUpdated Kind = "sidecar-pod-updated"
)

// Announcement is a struct for messages between various components of FSM signaling a need for a change in Sidecar proxy configuration
type Announcement struct {
	Type               Kind
	ReferencedObjectID interface{}
}
