#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include "bpf_macros.h"
#include "bpf_xtypes.h"
#include "bpf_xmaps.h"
#include "bpf_helpers.h"
#include "bpf_xflow.h"

#include "bpf_xcode.h"

char __LICENSE[] SEC("license") = "GPL";

SEC("classifier/pass")
int pass(skb_t *skb)
{
    return TC_ACT_OK;
}

SEC("classifier/drop")
int drop(skb_t *skb)
{
    return TC_ACT_SHOT;
}

INTERNAL(int) dispatch(skb_t *skb, xpkt_t *pkt, cfg_t *cfg, flags_t *flags)
{
    if (XFLAG_HAS(pkt->nfs[pkt->tc_dir], NF_XNAT)) {
        if (pkt->flow.proto == IPPROTO_TCP) {
            if (flags->trace_nat_on) {
                if (pkt->v6) {
                    FSM_DBG("[DBG] TCP SNAT [%pI6[]:%d\n", pkt->xaddr,
                            ntohs(pkt->xport));
                    FSM_DBG("[DBG] TCP DNAT [%pI6]:%d\n", pkt->raddr,
                            ntohs(pkt->rport));
                } else {
                    FSM_DBG("[DBG] TCP SNAT %pI4:%d\n", &pkt->xaddr4,
                            ntohs(pkt->xport));
                    FSM_DBG("[DBG] TCP DNAT %pI4:%d\n", &pkt->raddr4,
                            ntohs(pkt->rport));
                }
                FSM_DBG("[DBG] TCP SHW %02x:%02x:%02x\n", pkt->xmac[0],
                        pkt->xmac[1], pkt->xmac[2]);
                FSM_DBG("[DBG]         %02x:%02x:%02x\n", pkt->xmac[3],
                        pkt->xmac[4], pkt->xmac[5]);
                FSM_DBG("[DBG] TCP DHW %02x:%02x:%02x\n", pkt->rmac[0],
                        pkt->rmac[1], pkt->rmac[2]);
                FSM_DBG("[DBG]         %02x:%02x:%02x\n", pkt->rmac[3],
                        pkt->rmac[4], pkt->rmac[5]);
            }

            if (pkt->v6) {
                xpkt_csum_set_tcp_dst_ipv6(skb, pkt, pkt->raddr);
                xpkt_csum_set_tcp_src_ipv6(skb, pkt, pkt->xaddr);
            } else {
                xpkt_csum_set_tcp_dst_ipv4(skb, pkt, pkt->raddr4);
                xpkt_csum_set_tcp_src_ipv4(skb, pkt, pkt->xaddr4);
            }

            xpkt_csum_set_tcp_dst_port(skb, pkt, pkt->rport);
            xpkt_csum_set_tcp_src_port(skb, pkt, pkt->xport);

            void *start = XPKT_PTR(XPKT_DATA(skb));
            void *dend = XPKT_PTR(XPKT_DATA_END(skb));
            struct ethhdr *eth = XPKT_PTR(start);
            if ((void *)(eth + 1) > dend) {
                return TC_ACT_SHOT;
            }

            XMAC_COPY(eth->h_dest, pkt->rmac);
            XMAC_COPY(eth->h_source, pkt->xmac);
        } else if (pkt->flow.proto == IPPROTO_UDP) {
            if (flags->trace_nat_on) {
                if (pkt->v6) {
                    FSM_DBG("[DBG] UDP SNAT [%pI6]:%d\n", pkt->xaddr,
                            ntohs(pkt->xport));
                    FSM_DBG("[DBG] UDP DNAT [%pI6]:%d\n", pkt->raddr,
                            ntohs(pkt->rport));
                } else {
                    FSM_DBG("[DBG] UDP SNAT %pI4:%d\n", &pkt->xaddr4,
                            ntohs(pkt->xport));
                    FSM_DBG("[DBG] UDP DNAT %pI4:%d\n", &pkt->raddr4,
                            ntohs(pkt->rport));
                }
                FSM_DBG("[DBG] TCP SHW %02x:%02x:%02x\n", pkt->xmac[0],
                        pkt->xmac[1], pkt->xmac[2]);
                FSM_DBG("[DBG]         %02x:%02x:%02x\n", pkt->xmac[3],
                        pkt->xmac[4], pkt->xmac[5]);
                FSM_DBG("[DBG] TCP DHW %02x:%02x:%02x\n", pkt->rmac[0],
                        pkt->rmac[1], pkt->rmac[2]);
                FSM_DBG("[DBG]         %02x:%02x:%02x\n", pkt->rmac[3],
                        pkt->rmac[4], pkt->rmac[5]);
            }

            if (pkt->v6) {
                xpkt_csum_set_udp_dst_ipv6(skb, pkt, pkt->raddr);
                xpkt_csum_set_udp_src_ipv6(skb, pkt, pkt->xaddr);
            } else {
                xpkt_csum_set_udp_dst_ipv4(skb, pkt, pkt->raddr4);
                xpkt_csum_set_udp_src_ipv4(skb, pkt, pkt->xaddr4);
            }

            xpkt_csum_set_udp_dst_port(skb, pkt, pkt->rport);
            xpkt_csum_set_udp_src_port(skb, pkt, pkt->xport);

            void *start = XPKT_PTR(XPKT_DATA(skb));
            void *dend = XPKT_PTR(XPKT_DATA_END(skb));
            struct ethhdr *eth = XPKT_PTR(start);
            if ((void *)(eth + 1) > dend) {
                return TC_ACT_SHOT;
            }

            XMAC_COPY(eth->h_dest, pkt->rmac);
            XMAC_COPY(eth->h_source, pkt->xmac);
        }
    }

    if (XFLAG_HAS(pkt->nfs[pkt->tc_dir], NF_EXHW)) {
        void *start = XPKT_PTR(XPKT_DATA(skb));
        void *dend = XPKT_PTR(XPKT_DATA_END(skb));
        struct ethhdr *eth = XPKT_PTR(start);
        if ((void *)(eth + 1) > dend) {
            return TC_ACT_SHOT;
        }

        XMAC_COPY(eth->h_dest, pkt->smac);
        XMAC_COPY(eth->h_source, pkt->dmac);
    }

    if (XFLAG_HAS(pkt->nfs[pkt->tc_dir], NF_RDIR)) {
        if (pkt->ofi > 0) {
            if (flags->trace_nat_on) {
                FSM_DBG("[DBG] RDRT OFI: %d FLAGS: %d\n", pkt->ofi,
                        pkt->oflags);
            }
            return bpf_redirect(pkt->ofi, pkt->oflags);
        }

        if (flags->trace_nat_on) {
            FSM_DBG("[DBG] RDRT IFI: %d FLAGS: %d\n", pkt->ifi, 0);
        }
        return bpf_redirect(pkt->ifi, 0);
    }

    if (pkt->nfs[pkt->tc_dir] == NF_DENY) {
        return TC_ACT_SHOT;
    } else if (XFLAG_HAS(pkt->nfs[pkt->tc_dir], NF_ALLOW)) {
        if (flags->trace_nat_on) {
            FSM_DBG("[DBG] ALLOW \n");
        }
        return TC_ACT_OK;
    }

    if (flags->trace_nat_on) {
        FSM_DBG("[DBG] default by nfs %d\n", pkt->nfs[pkt->tc_dir]);
    }
    return TC_ACT_OK;
}

INTERNAL(int) process(skb_t *skb, xpkt_t *pkt)
{
    decoder_t decoder;
    decoder.start = XPKT_PTR(XPKT_DATA(skb));
    decoder.data_begin = XPKT_PTR(decoder.start);
    decoder.data_end = XPKT_PTR(XPKT_DATA_END(skb));

    int ret = decode_eth(&decoder, skb, pkt);
    if (ret != DECODE_PASS) {
        goto decode_fail;
    }

    cfg_t *cfg = bpf_map_lookup_elem(&fsm_xcfg, &pkt->flow.sys);
    if (!cfg) {
        return TC_ACT_SHOT;
    }

    pkt->l3_off = XPKT_PTR_SUB(decoder.data_begin, decoder.start);

    if (pkt->l2_type == htons(ETH_P_IP)) {
        if (cfg->ipv4.tflags.deny_all) {
            return TC_ACT_SHOT;
        } else if (cfg->ipv4.tflags.allow_all) {
            return TC_ACT_OK;
        }
        pkt->v6 = 0;
        ret = decode_ipv4(&decoder, skb, pkt);
    } else if (pkt->l2_type == htons(ETH_P_IPV6)) {
        if (cfg->ipv6.tflags.deny_all) {
            return TC_ACT_SHOT;
        } else if (cfg->ipv6.tflags.allow_all) {
            return TC_ACT_OK;
        }
        pkt->v6 = 1;
        ret = decode_ipv6(&decoder, skb, pkt);
    } else {
        return TC_ACT_OK;
    }

    if (ret != DECODE_PASS) {
        goto decode_fail;
    }

    void *xflow = NULL;
    void *xopt = NULL;
    flags_t *flags = NULL;
    if (pkt->v6) {
        flags = &cfg->ipv6.tflags;
        if (pkt->flow.proto == IPPROTO_TCP) {
            if (flags->tcp_proto_deny_all) {
                return TC_ACT_SHOT;
            }
            if (flags->tcp_proto_allow_all) {
                return TC_ACT_OK;
            }
            ret = decode_tcp(&decoder, skb, pkt);
            if (ret != DECODE_PASS) {
                goto decode_fail;
            }
            xflow = &fsm_tflow;
            xopt = &fsm_topt;
        } else if (pkt->flow.proto == IPPROTO_UDP) {
            if (flags->udp_proto_deny_all) {
                return TC_ACT_SHOT;
            }
            if (flags->udp_proto_allow_all) {
                return TC_ACT_OK;
            }
            ret = decode_udp(&decoder, skb, pkt);
            if (ret != DECODE_PASS) {
                goto decode_fail;
            }
            xflow = &fsm_uflow;
            xopt = &fsm_uopt;
        } else {
            if (flags->oth_proto_deny_all) {
                return TC_ACT_SHOT;
            }
            return TC_ACT_OK;
        }
    } else {
        flags = &cfg->ipv4.tflags;
        if (pkt->ipv4_frag == 0) {
            if (pkt->flow.proto == IPPROTO_TCP) {
                if (flags->tcp_proto_deny_all) {
                    return TC_ACT_SHOT;
                }
                if (flags->tcp_proto_allow_all) {
                    return TC_ACT_OK;
                }
                ret = decode_tcp(&decoder, skb, pkt);
                if (ret != DECODE_PASS) {
                    goto decode_fail;
                }
                xflow = &fsm_tflow;
                xopt = &fsm_topt;
            } else if (pkt->flow.proto == IPPROTO_UDP) {
                if (flags->udp_proto_deny_all) {
                    return TC_ACT_SHOT;
                }
                if (flags->udp_proto_allow_all) {
                    return TC_ACT_OK;
                }
                ret = decode_udp(&decoder, skb, pkt);
                if (ret != DECODE_PASS) {
                    goto decode_fail;
                }
                xflow = &fsm_uflow;
                xopt = &fsm_uopt;
            } else {
                if (flags->oth_proto_deny_all) {
                    return TC_ACT_SHOT;
                }
                return TC_ACT_OK;
            }
        }
    }

    if (flags->trace_by_ip_on || flags->trace_by_port_on) {
        xpkt_trace_check(skb, pkt, cfg, flags);
    }

    if (flags->trace_hdr_on) {
        FSM_DBG("\n");
        if (pkt->tc_dir == TC_DIR_IGR) {
            FSM_DBG("[DBG] TC --> INGRESS\n");
        }
        if (pkt->tc_dir == TC_DIR_EGR) {
            FSM_DBG("[DBG] TC EGRESS -->\n");
        }

        if (pkt->v6) {
            FSM_DBG("[DBG] SRC [%pI6]:%d\n", pkt->flow.saddr,
                    ntohs(pkt->flow.sport));
            FSM_DBG("[DBG] DST [%pI6]:%d\n", pkt->flow.daddr,
                    ntohs(pkt->flow.dport));
        } else {
            FSM_DBG("[DBG] SRC %pI4:%d\n", &pkt->flow.saddr4,
                    ntohs(pkt->flow.sport));
            FSM_DBG("[DBG] DST %pI4:%d\n", &pkt->flow.daddr4,
                    ntohs(pkt->flow.dport));
        }
        FSM_DBG("[DBG] SHW %02x:%02x:%02x\n", pkt->smac[0], pkt->smac[1],
                pkt->smac[2]);
        FSM_DBG("[DBG]     %02x:%02x:%02x\n", pkt->smac[3], pkt->smac[4],
                pkt->smac[5]);
        FSM_DBG("[DBG] DHW %02x:%02x:%02x\n", pkt->dmac[0], pkt->dmac[1],
                pkt->dmac[2]);
        FSM_DBG("[DBG]     %02x:%02x:%02x\n", pkt->dmac[3], pkt->dmac[4],
                pkt->dmac[5]);
        void *dend = XPKT_PTR(XPKT_DATA_END(skb));
        struct tcphdr *t = XPKT_PTR_ADD(XPKT_DATA(skb), pkt->l4_off);
        if ((void *)(t + 1) > dend) {
            return -1;
        }
        FSM_DBG("[DBG] SYN: %d ACK: %d FIN: %d\n", t->syn, t->ack, t->fin);
        FSM_DBG("[DBG] SEQ: %u ACK_SEQ: %u IFI: %u\n", ntohl(t->seq),
                ntohl(t->ack_seq), skb->ifindex);
    }

    if (pkt->flow.sys == SYS_NOOP) {
        return TC_ACT_OK;
    }

    if (flags->acl_check_on) {
        xpkt_acl_check(skb, pkt, cfg, flags);
        if (flags->trace_acl_on) {
            FSM_DBG("[DBG] ACL AUDIT\n");
        }
    }

#ifndef BPF_LARGE_INSNS_OFF
    __s8 trans = xpkt_flow_proc(skb, pkt, cfg, flags, xflow, xopt);
    if (flags->trace_hdr_on) {
        FSM_DBG("[DBG] TRANS: %d\n", trans);
    }
    return dispatch(skb, pkt, cfg, flags);
#else
    xpkt_tail_call(skb, pkt, FSM_CNI_FLOW_PROG_ID);
    return TC_ACT_SHOT;
#endif

decode_fail:
    if (ret < DECODE_OK) {
        return TC_ACT_SHOT;
    }
    return TC_ACT_SHOT;
}

INTERNAL(int) decode(skb_t *skb, xpkt_t *pkt)
{
    decoder_t decoder;
    decoder.start = XPKT_PTR(XPKT_DATA(skb));
    decoder.data_begin = XPKT_PTR(decoder.start);
    decoder.data_end = XPKT_PTR(XPKT_DATA_END(skb));

    int ret = decode_eth(&decoder, skb, pkt);
    if (ret != DECODE_PASS) {
        goto decode_fail;
    }

    cfg_t *cfg = bpf_map_lookup_elem(&fsm_xcfg, &pkt->flow.sys);
    if (!cfg) {
        return TC_ACT_SHOT;
    }

    pkt->l3_off = XPKT_PTR_SUB(decoder.data_begin, decoder.start);

    if (pkt->l2_type == htons(ETH_P_IP)) {
        if (cfg->ipv4.tflags.deny_all) {
            return TC_ACT_SHOT;
        } else if (cfg->ipv4.tflags.allow_all) {
            return TC_ACT_OK;
        }
        pkt->v6 = 0;
        ret = decode_ipv4(&decoder, skb, pkt);
    } else if (pkt->l2_type == htons(ETH_P_IPV6)) {
        if (cfg->ipv6.tflags.deny_all) {
            return TC_ACT_SHOT;
        } else if (cfg->ipv6.tflags.allow_all) {
            return TC_ACT_OK;
        }
        pkt->v6 = 1;
        ret = decode_ipv6(&decoder, skb, pkt);
    } else {
        return TC_ACT_OK;
    }

    if (ret != DECODE_PASS) {
        goto decode_fail;
    }

    flags_t *flags = NULL;
    if (pkt->v6) {
        flags = &cfg->ipv6.tflags;
        if (pkt->flow.proto == IPPROTO_TCP) {
            if (flags->tcp_proto_deny_all) {
                return TC_ACT_SHOT;
            }
            if (flags->tcp_proto_allow_all) {
                return TC_ACT_OK;
            }
            ret = decode_tcp(&decoder, skb, pkt);
            if (ret != DECODE_PASS) {
                goto decode_fail;
            }
        } else if (pkt->flow.proto == IPPROTO_UDP) {
            if (flags->udp_proto_deny_all) {
                return TC_ACT_SHOT;
            }
            if (flags->udp_proto_allow_all) {
                return TC_ACT_OK;
            }
            ret = decode_udp(&decoder, skb, pkt);
            if (ret != DECODE_PASS) {
                goto decode_fail;
            }
        } else {
            if (flags->oth_proto_deny_all) {
                return TC_ACT_SHOT;
            }
            return TC_ACT_OK;
        }
    } else {
        flags = &cfg->ipv4.tflags;
        if (pkt->ipv4_frag == 0) {
            if (pkt->flow.proto == IPPROTO_TCP) {
                if (flags->tcp_proto_deny_all) {
                    return TC_ACT_SHOT;
                }
                if (flags->tcp_proto_allow_all) {
                    return TC_ACT_OK;
                }
                ret = decode_tcp(&decoder, skb, pkt);
                if (ret != DECODE_PASS) {
                    goto decode_fail;
                }
            } else if (pkt->flow.proto == IPPROTO_UDP) {
                if (flags->udp_proto_deny_all) {
                    return TC_ACT_SHOT;
                }
                if (flags->udp_proto_allow_all) {
                    return TC_ACT_OK;
                }
                ret = decode_udp(&decoder, skb, pkt);
                if (ret != DECODE_PASS) {
                    goto decode_fail;
                }
            } else {
                if (flags->oth_proto_deny_all) {
                    return TC_ACT_SHOT;
                }
                return TC_ACT_OK;
            }
        }
    }

    FSM_DBG("\n");
    if (pkt->tc_dir == TC_DIR_IGR) {
        FSM_DBG("[DBG] TC --> INGRESS\n");
    }
    if (pkt->tc_dir == TC_DIR_EGR) {
        FSM_DBG("[DBG] TC EGRESS -->\n");
    }

    if (pkt->v6) {
        FSM_DBG("[DBG] SRC [%pI6]:%d\n", pkt->flow.saddr,
                ntohs(pkt->flow.sport));
        FSM_DBG("[DBG] DST [%pI6]:%d\n", pkt->flow.daddr,
                ntohs(pkt->flow.dport));
    } else {
        FSM_DBG("[DBG] SRC %pI4:%d\n", &pkt->flow.saddr4,
                ntohs(pkt->flow.sport));
        FSM_DBG("[DBG] DST %pI4:%d\n", &pkt->flow.daddr4,
                ntohs(pkt->flow.dport));
    }
    FSM_DBG("[DBG] SHW %02x:%02x:%02x\n", pkt->smac[0], pkt->smac[1],
            pkt->smac[2]);
    FSM_DBG("[DBG]     %02x:%02x:%02x\n", pkt->smac[3], pkt->smac[4],
            pkt->smac[5]);
    FSM_DBG("[DBG] DHW %02x:%02x:%02x\n", pkt->dmac[0], pkt->dmac[1],
            pkt->dmac[2]);
    FSM_DBG("[DBG]     %02x:%02x:%02x\n", pkt->dmac[3], pkt->dmac[4],
            pkt->dmac[5]);
    void *dend = XPKT_PTR(XPKT_DATA_END(skb));
    struct tcphdr *t = XPKT_PTR_ADD(XPKT_DATA(skb), pkt->l4_off);
    if ((void *)(t + 1) > dend) {
        return -1;
    }
    FSM_DBG("[DBG] SYN: %d ACK: %d FIN: %d\n", t->syn, t->ack, t->fin);
    FSM_DBG("[DBG] SEQ: %u ACK_SEQ: %u IFI: %u\n", ntohl(t->seq),
            ntohl(t->ack_seq), skb->ifindex);

    return TC_ACT_OK;

decode_fail:
    if (ret < DECODE_OK) {
        return TC_ACT_SHOT;
    }
    return TC_ACT_SHOT;
}

SEC("classifier/flow")
int flow(skb_t *skb)
{
#ifdef BPF_LARGE_INSNS_OFF
    int z = 0;
    xpkt_t *pkt = bpf_map_lookup_elem(&fsm_xpkt, &z);
    if (!pkt) {
        return TC_ACT_SHOT;
    }

    cfg_t *cfg = bpf_map_lookup_elem(&fsm_xcfg, &pkt->flow.sys);
    if (!cfg) {
        return TC_ACT_SHOT;
    }

    void *xflow = NULL;
    void *xopt = NULL;
    flags_t *flags = NULL;
    if (pkt->v6) {
        flags = &cfg->ipv6.tflags;
        if (pkt->flow.proto == IPPROTO_TCP) {
            xflow = &fsm_tflow;
            xopt = &fsm_topt;
        } else if (pkt->flow.proto == IPPROTO_UDP) {
            xflow = &fsm_uflow;
            xopt = &fsm_uopt;
        } else {
            if (flags->oth_proto_deny_all) {
                return TC_ACT_SHOT;
            }
            return TC_ACT_OK;
        }
    } else {
        flags = &cfg->ipv4.tflags;
        if (pkt->ipv4_frag == 0) {
            if (pkt->flow.proto == IPPROTO_TCP) {
                xflow = &fsm_tflow;
                xopt = &fsm_topt;
            } else if (pkt->flow.proto == IPPROTO_UDP) {
                xflow = &fsm_uflow;
                xopt = &fsm_uopt;
            } else {
                if (flags->oth_proto_deny_all) {
                    return TC_ACT_SHOT;
                }
                return TC_ACT_OK;
            }
        }
    }

    __s8 trans = xpkt_flow_proc(skb, pkt, cfg, flags, xflow, xopt);
    if (flags->trace_hdr_on) {
        FSM_DBG("[DBG] TRANS: %d\n", trans);
    }

    return dispatch(skb, pkt, cfg, flags);
#else
    return TC_ACT_SHOT;
#endif
}

SEC("classifier/noop/ingress")
int noop_ingress(skb_t *skb)
{
    int z = 0;
    xpkt_t *pkt = bpf_map_lookup_elem(&fsm_xpkt, &z);
    if (!pkt) {
        return TC_ACT_SHOT;
    }

    memset(pkt, 0, sizeof *pkt);
    pkt->tc_dir = TC_DIR_IGR;
    pkt->ifi = skb->ifindex;
    pkt->flow.sys = SYS_NOOP;

    return decode(skb, pkt);
}

SEC("classifier/noop/egress")
int noop_egress(skb_t *skb)
{
    int z = 0;
    xpkt_t *pkt = bpf_map_lookup_elem(&fsm_xpkt, &z);
    if (!pkt) {
        return TC_ACT_SHOT;
    }

    memset(pkt, 0, sizeof *pkt);
    pkt->tc_dir = TC_DIR_EGR;
    pkt->ifi = skb->ifindex;
    pkt->flow.sys = SYS_NOOP;

    return decode(skb, pkt);
}

SEC("classifier/mesh/ingress")
int mesh_ingress(skb_t *skb)
{
    int z = 0;
    xpkt_t *pkt = bpf_map_lookup_elem(&fsm_xpkt, &z);
    if (!pkt) {
        return TC_ACT_SHOT;
    }

    memset(pkt, 0, sizeof *pkt);
    pkt->tc_dir = TC_DIR_IGR;
    pkt->ifi = skb->ifindex;
    pkt->flow.sys = SYS_MESH;

    return process(skb, pkt);
}

SEC("classifier/mesh/egress")
int mesh_egress(skb_t *skb)
{
    int z = 0;
    xpkt_t *pkt = bpf_map_lookup_elem(&fsm_xpkt, &z);
    if (!pkt) {
        return TC_ACT_SHOT;
    }

    memset(pkt, 0, sizeof *pkt);
    pkt->tc_dir = TC_DIR_EGR;
    pkt->ifi = skb->ifindex;
    pkt->flow.sys = SYS_MESH;

    return process(skb, pkt);
}

SEC("classifier/e4lb/ingress")
int e4lb_ingress(skb_t *skb)
{
    int z = 0;
    xpkt_t *pkt = bpf_map_lookup_elem(&fsm_xpkt, &z);
    if (!pkt) {
        return TC_ACT_SHOT;
    }

    memset(pkt, 0, sizeof *pkt);
    pkt->tc_dir = TC_DIR_IGR;
    pkt->ifi = skb->ifindex;
    pkt->flow.sys = SYS_E4LB;

    return process(skb, pkt);
}

SEC("classifier/e4lb/egress")
int e4lb_egress(skb_t *skb)
{
    int z = 0;
    xpkt_t *pkt = bpf_map_lookup_elem(&fsm_xpkt, &z);
    if (!pkt) {
        return TC_ACT_SHOT;
    }

    memset(pkt, 0, sizeof *pkt);
    pkt->tc_dir = TC_DIR_EGR;
    pkt->ifi = skb->ifindex;
    pkt->flow.sys = SYS_E4LB;

    return process(skb, pkt);
}
