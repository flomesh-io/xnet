#ifndef __FSM_XNETWORK_MACROS_H__
#define __FSM_XNETWORK_MACROS_H__

#include "bpf_config.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#define memset(dest, c, n) __builtin_memset((dest), (c), (n))
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((unsigned long)&((TYPE *)0)->MEMBER)
#endif

#define XPKT_DATA(skb) ((skb)->data)
#define XPKT_DATA_END(skb) ((skb)->data_end)

#define XPKT_PTR(x) ((void *)((long)x))
#define XPKT_PTR_ADD(x, len) ((void *)(((__u8 *)((long)x)) + (len)))
#define XPKT_PTR_SUB(x, y) (((__u8 *)XPKT_PTR(x)) - ((__u8 *)XPKT_PTR(y)))

#ifndef IPV4_SINGLE_STACK
#define IP_ALEN 4
#define XADDR_COPY(dst, src) memcpy(dst, src, 16)
#define XADDR_ZERO(v) memset(v, 0, 16)
#define XADDR_IS_ZERO(v) (v[0] == 0 && v[1] == 0 && v[2] == 0 && v[3] == 0)
#else
#define IP_ALEN 1
#define XADDR_COPY(dst, src) memcpy(dst, src, 4)
#define XADDR_ZERO(v) memset(v, 0, 4)
#define XADDR_IS_ZERO(v) (v[0] == 0)
#endif

#define XMAC_COPY(dst, src) memcpy(dst, src, ETH_ALEN)
#define XMAC_ZERO(v) memset(v, 0, ETH_ALEN)
#define XMAC_IS_ZERO(v)                                                        \
    (v[0] == 0 && v[1] == 0 && v[2] == 0 && v[3] == 0 && v[4] == 0 && v[5] == 0)

#define XFLOW_COPY(dst, src) memcpy(dst, src, sizeof(flow_t))

#define XFLOW_OP_COPY(dst, src)                                                \
    dst->atime = src->atime;                                                   \
    dst->flow_dir = src->flow_dir;                                             \
    memcpy(&dst->xnat, &src->xnat, sizeof(xnat_t));                            \
    memcpy(&dst->trans, &src->trans, sizeof(trans_t));

#define XFUNC_COPY(dst, src) memcpy(dst, src, sizeof(__u8) * TC_DIR_MAX)
#define XFUNC_EXCH(dst, src)                                                   \
    (dst)[TC_DIR_IGR] = (src)[TC_DIR_EGR];                                     \
    (dst)[TC_DIR_EGR] = (src)[TC_DIR_IGR];

#define XFLAG_HAS(var, flag) (var & flag)

#define ETH_TYPE_ETH2(x) ((x) >= htons(1536))

#ifndef BPF_GLOBAL_DATE_OFF
#define debug_printf(fmt, ...)                                                 \
    do {                                                                       \
        static char _fmt[] = fmt;                                              \
        bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__);                   \
    } while (0)
#else
#define debug_printf(fmt, ...)                                                 \
    do {                                                                       \
        char _fmt[] = fmt;                                                     \
        bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__);                   \
    } while (0)
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define ntohs(x) __builtin_bswap16(x)
#define htons(x) __builtin_bswap16(x)
#define ntohl(x) __builtin_bswap32(x)
#define htonl(x) __builtin_bswap32(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define ntohs(x) (x)
#define htons(x) (x)
#define ntohl(x) (x)
#define htonl(x) (x)
#else
#error "Unknown __BYTE_ORDER__"
#endif

#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#endif