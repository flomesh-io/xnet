#ifndef __FSM_XNETWORK_XTRANS_H__
#define __FSM_XNETWORK_XTRANS_H__

#include "bpf_macros.h"
#include "bpf_debug.h"

INTERNAL(__s8)
xpkt_tcp_trans(skb_t *skb, xpkt_t *pkt, flow_op_t *cop, flow_op_t *rop,
               flow_dir_e flow_dir)
{
    tcp_trans_t *ctr = &cop->trans.tcp;
    tcp_trans_t *rtr = &rop->trans.tcp;
    void *dend = XPKT_PTR(XPKT_DATA_END(skb));
    struct tcphdr *t = XPKT_PTR_ADD(XPKT_DATA(skb), pkt->l4_off);
    __u8 tcp_flags = pkt->tcp_flags;
    tcp_conn_t *cconn = &ctr->conns[flow_dir];
    tcp_conn_t *rconn;
    __u32 seq, ack_seq;
    __u32 nstate = 0;

    if ((void *)(t + 1) > dend) {
        return -1;
    }

    seq = ntohl(t->seq);
    ack_seq = ntohl(t->ack_seq);

    xpkt_spin_lock(&cop->lock);

    if (flow_dir == FLOW_DIR_C2S) {
        cop->trans.tcp.conns[0].prev_seq = t->seq;
        cop->trans.tcp.conns[0].prev_ack_seq = t->ack_seq;
    } else {
        rop->trans.tcp.conns[0].prev_seq = t->seq;
        rop->trans.tcp.conns[0].prev_ack_seq = t->ack_seq;
    }

    rconn = &ctr->conns[flow_dir == FLOW_DIR_C2S ? FLOW_DIR_S2C : FLOW_DIR_C2S];

    if (tcp_flags & TCP_F_RST) {
        nstate = TCP_STATE_CWT;
        goto end;
    }

    switch (cop->trans.tcp.state) {
    case TCP_STATE_CLOSED:
        if (tcp_flags & TCP_F_ACK) {
            cconn->seq = seq;
            if (cconn->init_acks) {
                if (ack_seq > rconn->seq + 2) {
                    nstate = TCP_STATE_ERR;
                    goto end;
                }
            }
            cconn->init_acks++;
            if (cconn->init_acks >= TCP_INIT_ACK_THRESHOLD &&
                rconn->init_acks >= TCP_INIT_ACK_THRESHOLD) {
                nstate = TCP_STATE_EST;
                break;
            }
            nstate = TCP_STATE_ERR;
            goto end;
        }

        if ((tcp_flags & TCP_F_SYN) != TCP_F_SYN) {
            nstate = TCP_STATE_ERR;
            goto end;
        }

        if (ack_seq != 0 && flow_dir != FLOW_DIR_C2S) {
            nstate = TCP_STATE_ERR;
            goto end;
        }

        cconn->seq = seq;
        nstate = TCP_STATE_SYN_SEND;
        break;
    case TCP_STATE_SYN_SEND:
        if (flow_dir != FLOW_DIR_S2C) {
            if ((tcp_flags & TCP_F_SYN) == TCP_F_SYN) {
                cconn->seq = seq;
                nstate = TCP_STATE_SYN_SEND;
            } else {
                nstate = TCP_STATE_ERR;
            }
            goto end;
        }

        if ((tcp_flags & (TCP_F_SYN | TCP_F_ACK)) != (TCP_F_SYN | TCP_F_ACK)) {
            nstate = TCP_STATE_ERR;
            goto end;
        }

        if (ack_seq != rconn->seq + 1) {
            nstate = TCP_STATE_ERR;
            goto end;
        }

        cconn->seq = seq;
        nstate = TCP_STATE_SYN_ACK;
        break;

    case TCP_STATE_SYN_ACK:
        if (flow_dir != FLOW_DIR_C2S) {
            if ((tcp_flags & (TCP_F_SYN | TCP_F_ACK)) !=
                (TCP_F_SYN | TCP_F_ACK)) {
                nstate = TCP_STATE_ERR;
                goto end;
            }

            if (ack_seq != rconn->seq + 1) {
                nstate = TCP_STATE_ERR;
                goto end;
            }

            nstate = TCP_STATE_SYN_ACK;
            goto end;
        }

        if ((tcp_flags & TCP_F_SYN) == TCP_F_SYN) {
            cconn->seq = seq;
            nstate = TCP_STATE_SYN_SEND;
            goto end;
        }

        if ((tcp_flags & TCP_F_ACK) != TCP_F_ACK) {
            nstate = TCP_STATE_ERR;
            goto end;
        }

        if (ack_seq != rconn->seq + 1) {
            nstate = TCP_STATE_ERR;
            goto end;
        }

        cconn->seq = seq;
        nstate = TCP_STATE_EST;
        break;

    case TCP_STATE_EST:
        if (tcp_flags & TCP_F_FIN) {
            cop->trans.tcp.fin_dir = flow_dir;
            nstate = TCP_STATE_FINI;
            cconn->seq = seq;
        } else {
            nstate = TCP_STATE_EST;
        }
        break;

    case TCP_STATE_FINI:
        if (cop->trans.tcp.fin_dir != flow_dir) {
            if ((tcp_flags & (TCP_F_FIN | TCP_F_ACK)) ==
                (TCP_F_FIN | TCP_F_ACK)) {
                nstate = TCP_STATE_FIN3;
                cconn->seq = seq;
            } else if (tcp_flags & TCP_F_ACK) {
                nstate = TCP_STATE_FIN2;
                cconn->seq = seq;
            }
        }
        break;
    case TCP_STATE_FIN2:
        if (cop->trans.tcp.fin_dir != flow_dir) {
            if (tcp_flags & TCP_F_FIN) {
                nstate = TCP_STATE_FIN3;
                cconn->seq = seq;
            }
        }
        break;

    case TCP_STATE_FIN3:
        if (cop->trans.tcp.fin_dir == flow_dir) {
            if (tcp_flags & TCP_F_ACK) {
                nstate = TCP_STATE_CWT;
            }
        }
        break;

    default:
        break;
    }

end:
    cop->trans.tcp.state = nstate;
    rop->trans.tcp.state = nstate;

    if (nstate != TCP_STATE_ERR && flow_dir == FLOW_DIR_S2C) {
        rop->trans.tcp.conns[0].seq = seq;
    }

    xpkt_spin_unlock(&cop->lock);

    if (nstate == TCP_STATE_EST) {
        return TRANS_EST;
    } else if (nstate & TCP_STATE_CWT) {
        return TRANS_CWT;
    } else if (nstate & TCP_STATE_ERR) {
        return TRANS_ERR;
    } else if (nstate & TCP_STATE_FIN_MASK) {
        return TRANS_FIN;
    }

    return TRANS_CHS;
}

INTERNAL(__s8)
xpkt_udp_trans(skb_t *skb, xpkt_t *pkt, flow_op_t *cop, flow_op_t *rop,
               flow_dir_e flow_dir)
{
    udp_trans_t *ctr = &cop->trans.udp;
    udp_trans_t *rtr = &rop->trans.udp;

    xpkt_spin_lock(&cop->lock);
    cop->trans.udp.conns.pkts++;
    rop->trans.udp.conns.pkts++;
    xpkt_spin_unlock(&cop->lock);

    return TRANS_EST;
}

INTERNAL(__s8)
xpkt_trans_proc(skb_t *skb, xpkt_t *pkt, flow_op_t *caop, flow_op_t *raop,
                flow_dir_e flow_dir)
{
    __s8 trans = 0;
    switch (pkt->flow.proto) {
    case IPPROTO_TCP:
        trans = xpkt_tcp_trans(skb, pkt, caop, raop, flow_dir);
        break;
    case IPPROTO_UDP:
        trans = xpkt_udp_trans(skb, pkt, caop, raop, flow_dir);
        break;
    default:
        trans = TRANS_NON;
        break;
    }
    return trans;
}

#endif