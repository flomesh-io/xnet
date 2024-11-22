#ifndef __FSM_SIDECAR_XTYPES_H__
#define __FSM_SIDECAR_XTYPES_H__

#define INTERNAL(type) __attribute__((__always_inline__)) static inline type

typedef struct __sk_buff skb_t;

typedef struct xpkt_mesh_cfg_t {
    union {
        __u64 flags;
        struct {
            __u64 ipv6_proto_deny_all : 1;
            __u64 ipv4_tcp_proto_deny_all : 1;
            __u64 ipv4_tcp_proto_allow_all : 1;
            __u64 ipv4_udp_proto_deny_all : 1;
            __u64 ipv4_udp_proto_allow_all : 1;
            __u64 ipv4_oth_proto_deny_all : 1;
            __u64 ipv4_tcp_nat_by_ip_port_on : 1;
            __u64 ipv4_tcp_nat_by_ip_on : 1;
            __u64 ipv4_tcp_nat_all_off : 1;
            __u64 ipv4_tcp_nat_opt_on : 1;
            __u64 ipv4_tcp_nat_opt_with_local_addr_on : 1;
            __u64 ipv4_tcp_nat_opt_with_local_port_on : 1;
            __u64 ipv4_udp_nat_by_ip_port_on : 1;
            __u64 ipv4_udp_nat_by_ip_on : 1;
            __u64 ipv4_udp_nat_by_port_on : 1;
            __u64 ipv4_udp_nat_all_off : 1;
            __u64 ipv4_udp_nat_opt_on : 1;
            __u64 ipv4_udp_nat_opt_with_local_addr_on : 1;
            __u64 ipv4_udp_nat_opt_with_local_port_on : 1;
            __u64 ipv4_acl_check_on : 1;
            __u64 ipv4_trace_hdr_on : 1;
            __u64 ipv4_trace_nat_on : 1;
            __u64 ipv4_trace_opt_on : 1;
            __u64 ipv4_trace_acl_on : 1;
            __u64 ipv4_trace_flow_on : 1;
            __u64 ipv4_trace_by_ip_on : 1;
            __u64 ipv4_trace_by_port_on : 1;
        };
    };
} __attribute__((packed)) cfg_t;

#define saddr4 saddr[0]
#define daddr4 daddr[0]
#define xaddr4 xaddr[0]
#define raddr4 raddr[0]
#define laddr4 laddr[0]

typedef enum xpkt_tc_dir_e {
    TC_DIR_IGR = 0,
    TC_DIR_EGR = 1,
    TC_DIR_MAX
} tc_dir_e;

typedef enum xpkt_decode_e {
    DECODE_DENY = -2,
    DECODE_FAIL = -1,
    DECODE_OK = 0,
    DECODE_PASS = 1
} decode_e;

typedef struct xpkt_decoder_t {
    void *start;
    void *data_begin;
    void *data_end;
} decoder_t;

typedef struct xpkt_flow_t {
    __u32 daddr[IP_ALEN];
    __u32 saddr[IP_ALEN];
    __u16 dport;
    __u16 sport;
    __u8 proto;
    __u8 v6;
} __attribute__((packed)) flow_t;

typedef struct xpkt {
    __u32 ifi;
    flow_t flow;

    __u8 nfs[TC_DIR_MAX];

    __u8 v6 : 1;
    __u8 tc_dir : 2;
    __u8 flow_dir : 2;
    __u8 l4_fin : 1;
    __u8 re_flow : 1;

    __u16 l2_type;
    __u8 dmac[ETH_ALEN];
    __u8 smac[ETH_ALEN];

    __u8 l3_off;
    __u8 ipv4_frag;
    __u16 ipv4_id;

    __u8 l4_off;
    __u8 tcp_flags;
    __u32 tcp_seq;
    __u32 tcp_ack_seq;

    __u8 xmac[ETH_ALEN];
    __u8 rmac[ETH_ALEN];
    __u32 xaddr[IP_ALEN];
    __u32 raddr[IP_ALEN];
    __u16 xport;
    __u16 rport;
} __attribute__((packed)) xpkt_t;

typedef enum xpkt_nf_e {
    NF_DENY = 0,
    NF_ALLOW = 1,
    NF_XNAT = 2,
    NF_RDIR = 4,
    NF_SKIP_SM = 8,
    NF_MAX
} nf_e;

typedef __u8 nf_t;

typedef enum xpkt_flow_dir_e {
    FLOW_DIR_C2S = 0,
    FLOW_DIR_S2C = 1,
    FLOW_DIR_MAX
} flow_dir_e;

typedef enum xpkt_trans_e {
    TRANS_ERR = -1,
    TRANS_CHS = 0,
    TRANS_EST = 1,
    TRANS_FIN = 2,
    TRANS_CWT = 3,
    TRANS_NON = 4,
} trans_e;

typedef enum xpkt_tcp_flag_e {
    TCP_F_FIN = 0x01,
    TCP_F_SYN = 0x02,
    TCP_F_RST = 0x04,
    TCP_F_ACK = 0x10,
} tcp_flag_e;

#define TCP_STATE_FIN_MASK                                                     \
    (TCP_STATE_FINI | TCP_STATE_FIN2 | TCP_STATE_FIN3 | TCP_STATE_CWT)

typedef enum xpkt_tcp_state_e {
    TCP_STATE_CLOSED = 0x00,
    TCP_STATE_SYN_SEND = 0x01,
    TCP_STATE_SYN_ACK = 0x02,
    TCP_STATE_EST = 0x04,
    TCP_STATE_ERR = 0x08,
    TCP_STATE_FINI = 0x10,
    TCP_STATE_FIN2 = 0x20,
    TCP_STATE_FIN3 = 0x40,
    TCP_STATE_CWT = 0x80
} tcp_state_e;

typedef struct xpkt_tcp_conn_t {
#define TCP_INIT_ACK_THRESHOLD 3
    __u32 seq;
    __be32 prev_seq;
    __be32 prev_ack_seq;
    __u32 init_acks;
} tcp_conn_t;

typedef struct xpkt_udp_conn_t {
    __u32 pkts;
} udp_conn_t;

typedef struct xpkt_tcp_trans_t {
    tcp_conn_t conns[FLOW_DIR_MAX];
    __u8 state;
    __u8 fin_dir;
} tcp_trans_t;

typedef struct xpkt_udp_trans_t {
    udp_conn_t conns;
} udp_trans_t;

typedef struct xpkt_trans_t {
    union {
        tcp_trans_t tcp;
        udp_trans_t udp;
    };
} __attribute__((packed)) trans_t;

typedef struct xpkt_xnat_t {
    __u8 xmac[ETH_ALEN];
    __u8 rmac[ETH_ALEN];
    __u32 xaddr[IP_ALEN];
    __u32 raddr[IP_ALEN];
    __u16 xport;
    __u16 rport;
} xnat_t;

typedef struct xpkt_flow_op_t {
    struct bpf_spin_lock lock;
    __u8 flow_dir;
    __u8 fin;
    nf_t nfs[TC_DIR_MAX];
    __u64 atime;
    xnat_t xnat;
    trans_t trans;
    __u8 do_trans;
} flow_op_t;

typedef struct {
    __u32 daddr[IP_ALEN];
    __u16 dport;
    __u8 proto;
    __u8 v6;
    __u8 tc_dir;
} __attribute__((packed)) nat_key_t;

typedef struct {
    __u32 raddr[IP_ALEN];
    __u16 rport;
    __u8 rmac[ETH_ALEN];
    __u8 inactive;
} nat_ep_t;

typedef struct {
    struct bpf_spin_lock lock;
    __u16 ep_sel;
    __u16 ep_cnt;
    nat_ep_t eps[FSM_NAT_MAX_ENDPOINTS];
} nat_op_t;

typedef struct xpkt_opt_key_t {
    __u32 laddr[IP_ALEN];
    __u32 raddr[IP_ALEN];
    __u16 lport;
    __u16 rport;
    __u8 proto;
    __u8 v6;
} __attribute__((packed)) opt_key_t;

typedef struct xpkt_acl_key_t {
    __u32 addr[IP_ALEN];
    __u16 port;
    __u8 proto;
} __attribute__((packed)) acl_key_t;

typedef enum xpkt_acl_op_e {
    ACL_DENY = 0,
    ACL_AUDIT = 1,
    ACL_TRUSTED = 2
} acl_op_e;

typedef struct xpkt_acl_op_t {
    __u8 acl;
    __u8 flag;
    __u16 id;
} __attribute__((packed)) acl_op_t;

typedef struct xpkt_trace_ip_t {
    __u32 addr[IP_ALEN];
} __attribute__((packed)) tr_ip_t;

typedef struct xpkt_trace_port_t {
    __u16 port;
} __attribute__((packed)) tr_port_t;

typedef struct xpkt_trace_op_t {
    __u8 tc_dir[TC_DIR_MAX];
} __attribute__((packed)) tr_op_t;

#endif