#ifndef __FSM_XNETWORK_HELPERS_H__
#define __FSM_XNETWORK_HELPERS_H__

#include <linux/pkt_cls.h>
#include <stdio.h>
#include "bpf_macros.h"
#include "bpf_debug.h"

INTERNAL(int)
xpkt_csum_set_tcp_src_ipv4(skb_t *skb, xpkt_t *pkt, __be32 xaddr)
{
    int ip_csum_off = pkt->l3_off + offsetof(struct iphdr, check);
    int tcp_csum_off = pkt->l4_off + offsetof(struct tcphdr, check);
    int ip_src_off = pkt->l3_off + offsetof(struct iphdr, saddr);
    __be32 old_sip = pkt->flow.saddr4;

    bpf_l4_csum_replace(skb, tcp_csum_off, old_sip, xaddr,
                        BPF_F_PSEUDO_HDR | sizeof(xaddr));
    bpf_l3_csum_replace(skb, ip_csum_off, old_sip, xaddr, sizeof(xaddr));
    bpf_skb_store_bytes(skb, ip_src_off, &xaddr, sizeof(xaddr), 0);

    pkt->flow.saddr4 = xaddr;

    return 0;
}

INTERNAL(int)
xpkt_csum_set_tcp_src_ipv6(skb_t *skb, xpkt_t *pkt, __be32 *xaddr)
{
    int tcp_csum_off = pkt->l4_off + offsetof(struct tcphdr, check);
    int ip_src_off = pkt->l3_off + offsetof(struct ipv6hdr, saddr);
    __be32 *old_sip = pkt->flow.saddr;

    bpf_l4_csum_replace(skb, tcp_csum_off, old_sip[0], xaddr[0],
                        BPF_F_PSEUDO_HDR | sizeof(*xaddr));
    bpf_l4_csum_replace(skb, tcp_csum_off, old_sip[1], xaddr[1],
                        BPF_F_PSEUDO_HDR | sizeof(*xaddr));
    bpf_l4_csum_replace(skb, tcp_csum_off, old_sip[2], xaddr[2],
                        BPF_F_PSEUDO_HDR | sizeof(*xaddr));
    bpf_l4_csum_replace(skb, tcp_csum_off, old_sip[3], xaddr[3],
                        BPF_F_PSEUDO_HDR | sizeof(*xaddr));
    bpf_skb_store_bytes(skb, ip_src_off, xaddr, sizeof(pkt->flow.saddr), 0);

    XADDR_COPY(pkt->flow.saddr, xaddr);

    return 0;
}

INTERNAL(int)
xpkt_csum_set_tcp_dst_ipv4(skb_t *skb, xpkt_t *pkt, __be32 xaddr)
{
    int ip_csum_off = pkt->l3_off + offsetof(struct iphdr, check);
    int tcp_csum_off = pkt->l4_off + offsetof(struct tcphdr, check);
    int ip_dst_off = pkt->l3_off + offsetof(struct iphdr, daddr);
    __be32 old_dip = pkt->flow.daddr4;

    bpf_l4_csum_replace(skb, tcp_csum_off, old_dip, xaddr,
                        BPF_F_PSEUDO_HDR | sizeof(xaddr));
    bpf_l3_csum_replace(skb, ip_csum_off, old_dip, xaddr, sizeof(xaddr));
    bpf_skb_store_bytes(skb, ip_dst_off, &xaddr, sizeof(xaddr), 0);
    pkt->flow.daddr4 = xaddr;

    return 0;
}

INTERNAL(int)
xpkt_csum_set_tcp_dst_ipv6(skb_t *skb, xpkt_t *pkt, __be32 *xaddr)
{
    int tcp_csum_off = pkt->l4_off + offsetof(struct tcphdr, check);
    int ip_src_off = pkt->l3_off + offsetof(struct ipv6hdr, daddr);
    __be32 *old_sip = pkt->flow.daddr;

    bpf_l4_csum_replace(skb, tcp_csum_off, old_sip[0], xaddr[0],
                        BPF_F_PSEUDO_HDR | sizeof(*xaddr));
    bpf_l4_csum_replace(skb, tcp_csum_off, old_sip[1], xaddr[1],
                        BPF_F_PSEUDO_HDR | sizeof(*xaddr));
    bpf_l4_csum_replace(skb, tcp_csum_off, old_sip[2], xaddr[2],
                        BPF_F_PSEUDO_HDR | sizeof(*xaddr));
    bpf_l4_csum_replace(skb, tcp_csum_off, old_sip[3], xaddr[3],
                        BPF_F_PSEUDO_HDR | sizeof(*xaddr));
    bpf_skb_store_bytes(skb, ip_src_off, xaddr, sizeof(pkt->flow.daddr), 0);

    XADDR_COPY(pkt->flow.daddr, xaddr);

    return 0;
}

INTERNAL(int)
xpkt_csum_set_tcp_src_port(skb_t *skb, xpkt_t *pkt, __be16 xport)
{
    int tcp_csum_off = pkt->l4_off + offsetof(struct tcphdr, check);
    int tcp_sport_off = pkt->l4_off + offsetof(struct tcphdr, source);
    __be32 old_sport = pkt->flow.sport;

    if (pkt->ipv4_frag || !xport)
        return 0;

    bpf_l4_csum_replace(skb, tcp_csum_off, old_sport, xport, sizeof(xport));
    bpf_skb_store_bytes(skb, tcp_sport_off, &xport, sizeof(xport), 0);
    pkt->flow.sport = xport;

    return 0;
}

INTERNAL(int)
xpkt_csum_set_tcp_dst_port(skb_t *skb, xpkt_t *pkt, __be16 xport)
{
    int tcp_csum_off = pkt->l4_off + offsetof(struct tcphdr, check);
    int tcp_dport_off = pkt->l4_off + offsetof(struct tcphdr, dest);
    __be32 old_dport = pkt->flow.dport;

    if (pkt->ipv4_frag)
        return 0;

    bpf_l4_csum_replace(skb, tcp_csum_off, old_dport, xport, sizeof(xport));
    bpf_skb_store_bytes(skb, tcp_dport_off, &xport, sizeof(xport), 0);
    pkt->flow.dport = xport;

    return 0;
}

INTERNAL(int)
xpkt_csum_set_udp_src_ipv4(skb_t *skb, xpkt_t *pkt, __be32 xaddr)
{
    int ip_csum_off = pkt->l3_off + offsetof(struct iphdr, check);
    int udp_csum_off = pkt->l4_off + offsetof(struct udphdr, check);
    int ip_src_off = pkt->l3_off + offsetof(struct iphdr, saddr);
    __be32 old_sip = pkt->flow.saddr4;

    bpf_l4_csum_replace(skb, udp_csum_off, old_sip, xaddr,
                        BPF_F_PSEUDO_HDR | sizeof(xaddr));
    bpf_l3_csum_replace(skb, ip_csum_off, old_sip, xaddr, sizeof(xaddr));
    bpf_skb_store_bytes(skb, ip_src_off, &xaddr, sizeof(xaddr), 0);
    pkt->flow.saddr4 = xaddr;

    return 0;
}

INTERNAL(int)
xpkt_csum_set_udp_src_ipv6(skb_t *skb, xpkt_t *pkt, __be32 *xaddr)
{
    int udp_csum_off = pkt->l4_off + offsetof(struct udphdr, check);
    int ip_src_off = pkt->l3_off + offsetof(struct ipv6hdr, saddr);
    __be32 *old_sip = pkt->flow.saddr;

    bpf_l4_csum_replace(skb, udp_csum_off, old_sip[0], xaddr[0],
                        BPF_F_PSEUDO_HDR | sizeof(*xaddr));
    bpf_l4_csum_replace(skb, udp_csum_off, old_sip[1], xaddr[1],
                        BPF_F_PSEUDO_HDR | sizeof(*xaddr));
    bpf_l4_csum_replace(skb, udp_csum_off, old_sip[2], xaddr[2],
                        BPF_F_PSEUDO_HDR | sizeof(*xaddr));
    bpf_l4_csum_replace(skb, udp_csum_off, old_sip[3], xaddr[3],
                        BPF_F_PSEUDO_HDR | sizeof(*xaddr));
    bpf_skb_store_bytes(skb, ip_src_off, xaddr, sizeof(pkt->flow.saddr), 0);
    XADDR_COPY(pkt->flow.saddr, xaddr);

    return 0;
}

INTERNAL(int)
xpkt_csum_set_udp_dst_ipv4(skb_t *skb, xpkt_t *pkt, __be32 xaddr)
{
    int ip_csum_off = pkt->l3_off + offsetof(struct iphdr, check);
    int udp_csum_off = pkt->l4_off + offsetof(struct udphdr, check);
    int ip_dst_off = pkt->l3_off + offsetof(struct iphdr, daddr);
    __be32 old_dip = pkt->flow.daddr4;

    bpf_l4_csum_replace(skb, udp_csum_off, old_dip, xaddr,
                        BPF_F_PSEUDO_HDR | sizeof(xaddr));
    bpf_l3_csum_replace(skb, ip_csum_off, old_dip, xaddr, sizeof(xaddr));
    bpf_skb_store_bytes(skb, ip_dst_off, &xaddr, sizeof(xaddr), 0);
    pkt->flow.daddr4 = xaddr;

    return 0;
}

INTERNAL(int)
xpkt_csum_set_udp_dst_ipv6(skb_t *skb, xpkt_t *pkt, __be32 *xaddr)
{
    int udp_csum_off = pkt->l4_off + offsetof(struct udphdr, check);
    int ip_src_off = pkt->l3_off + offsetof(struct ipv6hdr, daddr);
    __be32 *old_sip = pkt->flow.daddr;

    bpf_l4_csum_replace(skb, udp_csum_off, old_sip[0], xaddr[0],
                        BPF_F_PSEUDO_HDR | sizeof(*xaddr));
    bpf_l4_csum_replace(skb, udp_csum_off, old_sip[1], xaddr[1],
                        BPF_F_PSEUDO_HDR | sizeof(*xaddr));
    bpf_l4_csum_replace(skb, udp_csum_off, old_sip[2], xaddr[2],
                        BPF_F_PSEUDO_HDR | sizeof(*xaddr));
    bpf_l4_csum_replace(skb, udp_csum_off, old_sip[3], xaddr[3],
                        BPF_F_PSEUDO_HDR | sizeof(*xaddr));
    bpf_skb_store_bytes(skb, ip_src_off, xaddr, sizeof(pkt->flow.daddr), 0);
    XADDR_COPY(pkt->flow.daddr, xaddr);

    return 0;
}

INTERNAL(int)
xpkt_csum_set_udp_src_port(skb_t *skb, xpkt_t *pkt, __be16 xport)
{
    int udp_csum_off = pkt->l4_off + offsetof(struct udphdr, check);
    int udp_sport_off = pkt->l4_off + offsetof(struct udphdr, source);
    __be32 old_sport = pkt->flow.sport;

    if (pkt->ipv4_frag || !xport)
        return 0;

    bpf_l4_csum_replace(skb, udp_csum_off, old_sport, xport, sizeof(xport));
    bpf_skb_store_bytes(skb, udp_sport_off, &xport, sizeof(xport), 0);
    pkt->flow.sport = xport;

    return 0;
}

INTERNAL(int)
xpkt_csum_set_udp_dst_port(skb_t *skb, xpkt_t *pkt, __be16 xport)
{
    int udp_csum_off = pkt->l4_off + offsetof(struct udphdr, check);
    int udp_dport_off = pkt->l4_off + offsetof(struct udphdr, dest);
    __be32 old_dport = pkt->flow.dport;

    if (pkt->ipv4_frag)
        return 0;

    bpf_l4_csum_replace(skb, udp_csum_off, old_dport, xport, sizeof(xport));
    bpf_skb_store_bytes(skb, udp_dport_off, &xport, sizeof(xport), 0);
    pkt->flow.dport = xport;

    return 0;
}

INTERNAL(int)
xpkt_tail_call(skb_t *skb, xpkt_t *pkt, __u32 prog_id)
{
    int idx = 0;
    bpf_map_update_elem(&fsm_xpkt, &idx, pkt, BPF_ANY);
    bpf_tail_call(skb, &fsm_prog, prog_id);
    return TC_ACT_OK;
}

INTERNAL(int)
xpkt_spin_lock(struct bpf_spin_lock *lock)
{
#ifndef SPIN_LOCK_OFF
    bpf_spin_lock(lock);
#endif
    return 0;
}

INTERNAL(int)
xpkt_spin_unlock(struct bpf_spin_lock *lock)
{
#ifndef SPIN_LOCK_OFF
    bpf_spin_unlock(lock);
#endif
    return 0;
}

#endif