#ifndef __FSM_XNETWORK_SECTION_H__
#define __FSM_XNETWORK_SECTION_H__

#ifdef SUPPORTED_SECTION_TC

#define TC_PASS "tc"
#define TC_DROP "tc"

#define TC_FLOW "tc"

#define TC_NOOP_INGRESS "tc"
#define TC_NOOP_EGRESS "tc"

#define TC_MESH_INGRESS "tc"
#define TC_MESH_EGRESS "tc"

#define TC_E4LB_INGRESS "tc"
#define TC_E4LB_EGRESS "tc"

#else

#define TC_PASS "classifier/pass"
#define TC_DROP "classifier/drop"

#define TC_FLOW "classifier/flow"

#define TC_NOOP_INGRESS "classifier/noop/ingress"
#define TC_NOOP_EGRESS "classifier/noop/egress"

#define TC_MESH_INGRESS "classifier/mesh/ingress"
#define TC_MESH_EGRESS "classifier/mesh/egress"

#define TC_E4LB_INGRESS "classifier/e4lb/ingress"
#define TC_E4LB_EGRESS "classifier/e4lb/egress"

#endif

#endif