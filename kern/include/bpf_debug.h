#ifndef __FSM_SIDECAR_DEBUG_H__
#define __FSM_SIDECAR_DEBUG_H__

#define FSM_DBG debug_printf

#define FSM_DBG_FLOW(msg, flow)                                                \
    FSM_DBG("[DBG] " msg);                                                     \
    FSM_DBG("[DBG]   SRC %pI4:%d\n", &(flow)->saddr4, ntohs((flow)->sport));   \
    FSM_DBG("[DBG]   DST %pI4:%d\n", &(flow)->daddr4, ntohs((flow)->dport));

#define FSM_DBG_NAT_OPT(msg, src, flow)                                        \
    FSM_DBG("[DBG] " msg);                                                     \
    FSM_DBG("[DBG]   OPT KEY-> PROTO: %d\n", (src)->proto);                    \
    FSM_DBG("[DBG]   OPT KEY-> RMT %pI4:%d \n", &(src)->raddr4,                \
            ntohs((src)->rport));                                              \
    FSM_DBG("[DBG]   OPT KEY-> LOC %pI4:%d \n", &(src)->laddr4,                \
            ntohs((src)->lport));                                              \
    FSM_DBG("[DBG]   OPT ORI-> SRC %pI4:%d\n", &(flow)->saddr4,                \
            ntohs((flow)->sport));                                             \
    FSM_DBG("[DBG]   OPT ORI-> DST %pI4:%d\n", &(flow)->daddr4,                \
            ntohs((flow)->dport));

#endif