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
	FSM_PASS_PROG_KEY = uint32(0)
	FSM_DROP_PROG_KEY = uint32(1)
	FSM_FLOW_PROG_KEY = uint32(2)
)

const (
	FSM_NOOP_INGRESS_PROG_NAME = `classifier_noop_ingress`
	FSM_NOOP_EGRESS_PROG_NAME  = `classifier_noop_egress`

	FSM_MESH_INGRESS_PROG_NAME = `classifier_mesh_ingress`
	FSM_MESH_EGRESS_PROG_NAME  = `classifier_mesh_egress`

	FSM_E4LB_INGRESS_PROG_NAME = `classifier_e4lb_ingress`
	FSM_E4LB_EGRESS_PROG_NAME  = `classifier_e4lb_egress`

	FSM_PASS_PROG_NAME = `classifier_pass`
	FSM_DROP_PROG_NAME = `classifier_drop`
	FSM_FLOW_PROG_NAME = `classifier_flow`
)
