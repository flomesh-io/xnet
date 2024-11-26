package bpf

const (
	FSM_PROG_NAME = `fsm`
)

const (
	FSM_MAP_NAME_PROG       = `fsm_prog`
	FSM_MAP_NAME_NAT        = `fsm_xnat`
	FSM_MAP_NAME_ACL        = `fsm_xacl`
	FSM_MAP_NAME_TCP_FLOW   = `fsm_tflow`
	FSM_MAP_NAME_UDP_FLOW   = `fsm_uflow`
	FSM_MAP_NAME_TCP_OPT    = `fsm_topt`
	FSM_MAP_NAME_UDP_OPT    = `fsm_uopt`
	FSM_MAP_NAME_CFG        = `fsm_xcfg`
	FSM_MAP_NAME_IFS        = `fsm_xifs`
	FSM_MAP_NAME_TRACE_IP   = `fsm_trip`
	FSM_MAP_NAME_TRACE_PORT = `fsm_trpt`
)

const (
	FSM_CNI_PASS_PROG_KEY = uint32(0)
	FSM_CNI_DROP_PROG_KEY = uint32(1)
)

const (
	FSM_CNI_INGRESS_PROG_NAME = `classifier_sidecar_ingress`
	FSM_CNI_EGRESS_PROG_NAME  = `classifier_sidecar_egress`

	FSM_CNI_PASS_PROG_NAME = `classifier_pass`
	FSM_CNI_DROP_PROG_NAME = `classifier_drop`
)
