package constants

// Annotations used by the control plane
const (
	// SidecarUniqueIDLabelName is the label applied to pods with the unique ID of the sidecar.
	SidecarUniqueIDLabelName = "fsm-proxy-uuid"

	// SidecarPodLabelName is the annotation used for sidecar pod
	SidecarPodLabelName = "app"

	// SidecarPodLabelValue is the annotation used for sidecar pod
	SidecarPodLabelValue = "fsm-gateway"

	// SidecarNamespaceLabelName is the annotation used for sidecar pod
	SidecarNamespaceLabelName = "gateway.flomesh.io/ns"

	// EnvVarHumanReadableLogMessages is an environment variable, which when set to "true" enables colorful human-readable log messages.
	EnvVarHumanReadableLogMessages = "FSM_HUMAN_DEBUG_LOG"

	// FSMKubeResourceMonitorAnnotation is the key of the annotation used to monitor a K8s resource
	FSMKubeResourceMonitorAnnotation = "flomesh.io/monitored-by"
)
