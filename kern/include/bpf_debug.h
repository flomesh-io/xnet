#ifndef __FSM_XNETWORK_DEBUG_H__
#define __FSM_XNETWORK_DEBUG_H__

#ifndef BPF_DEBUG_OFF
#define FSM_DBG debug_printf
#else
#define FSM_DBG(fmt, ...)                                                      \
    do {                                                                       \
    } while (0)
#endif

#define FSM_DBG_FLOW(msg, flow, v6)                                            \
    FSM_DBG("[DBG] " msg);                                                     \
    if (v6) {                                                                  \
        FSM_DBG("[DBG]   SRC [%pI6]:%d\n", (flow)->saddr,                      \
                ntohs((flow)->sport));                                         \
        FSM_DBG("[DBG]   DST [%pI6]:%d\n", (flow)->daddr,                      \
                ntohs((flow)->dport));                                         \
    } else {                                                                   \
        FSM_DBG("[DBG]   SRC %pI4:%d\n", &(flow)->saddr4,                      \
                ntohs((flow)->sport));                                         \
        FSM_DBG("[DBG]   DST %pI4:%d\n", &(flow)->daddr4,                      \
                ntohs((flow)->dport));                                         \
    }

#define FSM_DBG_NAT_OPT(msg, src, flow, v6)                                    \
    FSM_DBG("[DBG] " msg);                                                     \
    FSM_DBG("[DBG]   OPT KEY-> PROTO: %d\n", (src)->proto);                    \
    if (v6) {                                                                  \
        FSM_DBG("[DBG]   OPT KEY-> RMT [%pI6]:%d \n", (src)->raddr,            \
                ntohs((src)->rport));                                          \
        FSM_DBG("[DBG]   OPT KEY-> LOC [%pI6]:%d \n", (src)->laddr,            \
                ntohs((src)->lport));                                          \
        FSM_DBG("[DBG]   OPT ORI-> SRC [%pI6]:%d\n", (flow)->saddr,            \
                ntohs((flow)->sport));                                         \
        FSM_DBG("[DBG]   OPT ORI-> DST [%pI6]:%d\n", (flow)->daddr,            \
                ntohs((flow)->dport));                                         \
    } else {                                                                   \
        FSM_DBG("[DBG]   OPT KEY-> RMT %pI4:%d \n", &(src)->raddr4,            \
                ntohs((src)->rport));                                          \
        FSM_DBG("[DBG]   OPT KEY-> LOC %pI4:%d \n", &(src)->laddr4,            \
                ntohs((src)->lport));                                          \
        FSM_DBG("[DBG]   OPT ORI-> SRC %pI4:%d\n", &(flow)->saddr4,            \
                ntohs((flow)->sport));                                         \
        FSM_DBG("[DBG]   OPT ORI-> DST %pI4:%d\n", &(flow)->daddr4,            \
                ntohs((flow)->dport));                                         \
    }

#endif