#ifndef __FSM_XNETWORK_DEBUG_H__
#define __FSM_XNETWORK_DEBUG_H__

#ifdef BPF_DEBUG_OFF
#define FSM_TRACE_HDR_OFF 1
#define FSM_TRACE_ACL_OFF 1
#define FSM_TRACE_NAT_OFF 1
#define FSM_TRACE_FLOW_OFF 1
#define FSM_TRACE_OPT_OFF 1
#endif

#ifndef FSM_TRACE_HDR_OFF
#define FSM_TRACE_HDR_PRINTF debug_printf
#else
#define FSM_TRACE_HDR_PRINTF(fmt, ...)
#endif

#ifndef FSM_TRACE_ACL_OFF
#define FSM_TRACE_ACL_PRINTF debug_printf
#else
#define FSM_TRACE_ACL_PRINTF(fmt, ...)
#endif

#ifndef FSM_TRACE_NAT_OFF
#define FSM_TRACE_NAT_PRINTF debug_printf
#else
#define FSM_TRACE_NAT_PRINTF(fmt, ...)
#endif

#ifndef FSM_TRACE_FLOW_OFF
#define FSM_TRACE_FLOW_PRINTF debug_printf
#define FSM_TRACE_FLOW(msg, flow, v6)                                          \
    FSM_TRACE_FLOW_PRINTF("[FLW] " msg);                                       \
    if (v6) {                                                                  \
        FSM_TRACE_FLOW_PRINTF("[FLW]   SRC [%pI6]:%d\n", (flow)->saddr,        \
                              ntohs((flow)->sport));                           \
        FSM_TRACE_FLOW_PRINTF("[FLW]   DST [%pI6]:%d\n", (flow)->daddr,        \
                              ntohs((flow)->dport));                           \
    } else {                                                                   \
        FSM_TRACE_FLOW_PRINTF("[FLW]   SRC %pI4:%d\n", &(flow)->saddr4,        \
                              ntohs((flow)->sport));                           \
        FSM_TRACE_FLOW_PRINTF("[FLW]   DST %pI4:%d\n", &(flow)->daddr4,        \
                              ntohs((flow)->dport));                           \
    }
#else
#define FSM_TRACE_FLOW_PRINTF(fmt, ...)
#define FSM_TRACE_FLOW(fmt, ...)
#endif

#ifndef FSM_TRACE_OPT_OFF
#define FSM_TRACE_OPT_PRINTF debug_printf
#define FSM_TRACE_OPT(msg, src, flow, v6)                                      \
    FSM_TRACE_OPT_PRINTF("[OPT] " msg);                                        \
    FSM_TRACE_OPT_PRINTF("[OPT]   OPT KEY-> PROTO: %d\n", (src)->proto);       \
    if (v6) {                                                                  \
        FSM_TRACE_OPT_PRINTF("[OPT]   OPT KEY-> RMT [%pI6]:%d \n",             \
                             (src)->raddr, ntohs((src)->rport));               \
        FSM_TRACE_OPT_PRINTF("[OPT]   OPT KEY-> LOC [%pI6]:%d \n",             \
                             (src)->laddr, ntohs((src)->lport));               \
        FSM_TRACE_OPT_PRINTF("[OPT]   OPT ORI-> SRC [%pI6]:%d\n",              \
                             (flow)->saddr, ntohs((flow)->sport));             \
        FSM_TRACE_OPT_PRINTF("[OPT]   OPT ORI-> DST [%pI6]:%d\n",              \
                             (flow)->daddr, ntohs((flow)->dport));             \
    } else {                                                                   \
        FSM_TRACE_OPT_PRINTF("[OPT]   OPT KEY-> RMT %pI4:%d \n",               \
                             &(src)->raddr4, ntohs((src)->rport));             \
        FSM_TRACE_OPT_PRINTF("[OPT]   OPT KEY-> LOC %pI4:%d \n",               \
                             &(src)->laddr4, ntohs((src)->lport));             \
        FSM_TRACE_OPT_PRINTF("[OPT]   OPT ORI-> SRC %pI4:%d\n",                \
                             &(flow)->saddr4, ntohs((flow)->sport));           \
        FSM_TRACE_OPT_PRINTF("[OPT]   OPT ORI-> DST %pI4:%d\n",                \
                             &(flow)->daddr4, ntohs((flow)->dport));           \
    }
#else
#define FSM_TRACE_OPT_PRINTF(fmt, ...)
#define FSM_TRACE_OPT(fmt, ...)
#endif

#endif