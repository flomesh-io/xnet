#ifndef __FSM_SIDECAR_XMAPS_H__
#define __FSM_SIDECAR_XMAPS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") fsm_prog = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = FSM_PROGS_MAP_ENTRIES,
};
#else /* BTF definitions */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, FSM_PROGS_MAP_ENTRIES);
} fsm_prog SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") fsm_xpkt = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(xpkt_t),
    .max_entries = 1,
};
#else /* BTF definitions */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, xpkt_t);
    __uint(max_entries, 1);
} fsm_xpkt SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") fsm_xacl = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(acl_key_t),
    .value_size = sizeof(acl_op_t),
    .max_entries = FSM_ACL_MAP_ENTRIES,
};
#else /* BTF definitions */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, acl_key_t);
    __type(value, acl_op_t);
    __uint(max_entries, FSM_ACL_MAP_ENTRIES);
} fsm_xacl SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") fsm_xnat = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(nat_key_t),
    .value_size = sizeof(nat_op_t),
    .max_entries = FSM_NAT_MAP_ENTRIES,
};
#else /* BTF definitions */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, nat_key_t);
    __type(value, nat_op_t);
    __uint(max_entries, FSM_NAT_MAP_ENTRIES);
} fsm_xnat SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") fsm_xflop = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(flow_op_t),
    .max_entries = 2,
};
#else /* BTF definitions */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, flow_op_t);
    __uint(max_entries, 2);
} fsm_xflop SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") fsm_tflow = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(flow_t),
    .value_size = sizeof(flow_op_t),
    .max_entries = FSM_FLOW_MAP_ENTRIES,
};
#else /* BTF definitions */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, flow_t);
    __type(value, flow_op_t);
    __uint(max_entries, FSM_FLOW_MAP_ENTRIES);
} fsm_tflow SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") fsm_uflow = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(flow_t),
    .value_size = sizeof(flow_op_t),
    .max_entries = FSM_FLOW_MAP_ENTRIES,
};
BPF_ANNOTATE_KV_PAIR(fsm_uflow, xpkt_flow_t, xpkt_flow_op_t);
#else /* BTF definitions */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, flow_t);
    __type(value, flow_op_t);
    __uint(max_entries, FSM_FLOW_MAP_ENTRIES);
} fsm_uflow SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") fsm_topt = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(opt_key_t),
    .value_size = sizeof(flow_t),
    .max_entries = FSM_FLOW_MAP_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};
#else /* BTF definitions */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, opt_key_t);
    __type(value, flow_t);
    __uint(max_entries, FSM_FLOW_MAP_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} fsm_topt SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") fsm_uopt = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(opt_key_t),
    .value_size = sizeof(flow_t),
    .max_entries = FSM_FLOW_MAP_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};
#else /* BTF definitions */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, opt_key_t);
    __type(value, flow_t);
    __uint(max_entries, FSM_FLOW_MAP_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} fsm_uopt SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") fsm_xcfg = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(cfg_t),
    .max_entries = SYS_MAX,
};
#else /* BTF definitions */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, cfg_t);
    __uint(max_entries, SYS_MAX);
} fsm_xcfg SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") fsm_trip = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(tr_ip_t),
    .value_size = sizeof(tr_op_t),
    .max_entries = FSM_TRACE_MAP_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};
#else /* BTF definitions */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, tr_ip_t);
    __type(value, tr_op_t);
    __uint(max_entries, FSM_TRACE_MAP_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} fsm_trip SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") fsm_trpt = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(tr_port_t),
    .value_size = sizeof(tr_op_t),
    .max_entries = FSM_TRACE_MAP_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};
#else /* BTF definitions */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, tr_port_t);
    __type(value, tr_op_t);
    __uint(max_entries, FSM_TRACE_MAP_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} fsm_trpt SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") fsm_xifs = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(if_name_t),
    .value_size = sizeof(if_info_t),
    .max_entries = FSM_IFACE_MAP_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};
#else /* BTF definitions */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, if_name_t);
    __type(value, if_info_t);
    __uint(max_entries, FSM_IFACE_MAP_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} fsm_xifs SEC(".maps");
#endif

#endif