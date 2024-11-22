#ifndef __FSM_SIDECAR_XCODE_H__
#define __FSM_SIDECAR_XCODE_H__

#include <linux/if_packet.h>
#include "bpf_xtypes.h"
#include "bpf_macros.h"
#include "bpf_debug.h"

#define IP_MF 0x2000     /* Flag: "More Fragments"	*/
#define IP_OFFSET 0x1FFF /* "Fragment Offset" part	*/

INTERNAL(int) ip_fragment(const struct iphdr *iph)
{
    return (iph->frag_off & htons(IP_MF | IP_OFFSET)) != 0;
}

INTERNAL(int) ip_first_fragment(const struct iphdr *iph)
{
    return (iph->frag_off & htons(IP_OFFSET)) == 0;
}

INTERNAL(int)
decode_eth(decoder_t *decoder, void *skb, xpkt_t *pkt)
{
    struct ethhdr *eth;

    eth = XPKT_PTR(decoder->data_begin);
    if ((void *)(eth + 1) > decoder->data_end) {
        return DECODE_FAIL;
    }

    XMAC_COPY(pkt->dmac, eth->h_dest);
    XMAC_COPY(pkt->smac, eth->h_source);
    pkt->l2_type = eth->h_proto;

    if (!ETH_TYPE_ETH2(eth->h_proto)) {
        return DECODE_PASS;
    }

    decoder->data_begin = XPKT_PTR_ADD(eth, sizeof(*eth));

    return DECODE_PASS;
}

INTERNAL(int)
decode_ipv4(decoder_t *decoder, void *skb, xpkt_t *pkt)
{
    struct iphdr *iph = XPKT_PTR(decoder->data_begin);
    int iphl = iph->ihl << 2;

    if ((void *)(iph + 1) > decoder->data_end) {
        return DECODE_FAIL;
    }

    if (XPKT_PTR_ADD(iph, iphl) > decoder->data_end) {
        return DECODE_FAIL;
    }

    pkt->flow.proto = iph->protocol;
    pkt->flow.saddr4 = iph->saddr;
    pkt->flow.daddr4 = iph->daddr;

    if (ip_first_fragment(iph)) {
        pkt->l4_off = XPKT_PTR_SUB(XPKT_PTR_ADD(iph, iphl), decoder->start);
        decoder->data_begin = XPKT_PTR_ADD(iph, iphl);
        if (ip_fragment(iph)) {
            pkt->ipv4_id = iph->id;
            pkt->re_flow = 1;
        }
    } else {
        if (ip_fragment(iph)) {
            pkt->flow.sport = iph->id;
            pkt->flow.dport = iph->id;
            pkt->ipv4_id = iph->id;
            pkt->ipv4_frag = 1;
        }
    }

    return DECODE_PASS;
}

INTERNAL(int)
decode_tcp(decoder_t *decoder, void *skb, xpkt_t *pkt)
{
    struct tcphdr *tcp = XPKT_PTR(decoder->data_begin);
    __u8 tcp_flags = 0;

    if ((void *)(tcp + 1) > decoder->data_end) {
        /* In case of fragmented packets */
        return DECODE_OK;
    }

    if (tcp->fin)
        tcp_flags = TCP_F_FIN;
    if (tcp->rst)
        tcp_flags |= TCP_F_RST;
    if (tcp->syn)
        tcp_flags |= TCP_F_SYN;
    if (tcp->ack)
        tcp_flags |= TCP_F_ACK;

    if (tcp_flags & (TCP_F_FIN | TCP_F_RST)) {
        pkt->l4_fin = 1;
    }

    pkt->flow.sport = tcp->source;
    pkt->flow.dport = tcp->dest;
    pkt->tcp_seq = tcp->seq;
    pkt->tcp_flags = tcp_flags;

    return DECODE_PASS;
}

INTERNAL(int)
decode_udp(decoder_t *decoder, void *skb, xpkt_t *pkt)
{
    struct udphdr *udp = XPKT_PTR(decoder->data_begin);

    if ((void *)(udp + 1) > decoder->data_end) {
        /* In case of fragmented packets */
        return DECODE_OK;
    }

    pkt->flow.sport = udp->source;
    pkt->flow.dport = udp->dest;

    return DECODE_PASS;
}

#endif