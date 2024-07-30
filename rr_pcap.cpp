/*
 *  ____  ____  _____              
 * |  _ \|  _ \|  ___|   _ ________
 * | |_) | |_) | |_ | | | |_  /_  /
 * |  _ <|  _ <|  _|| |_| |/ / / / 
 * |_| \_\_| \_\_|   \__,_/___/___|
 *
 * Copyright (C) National University of Singapore
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

static bool option_validate = false;        // Validate checksums

/*
 * PCAP file & packet headers.
 */
struct pcap_s                   // PCAP file header
{
    uint32_t magic;
    uint16_t major;
    uint16_t minor;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t snaplen;
    uint32_t linktype:28;
    uint32_t f:1;
    uint32_t fcs:3;
};
#define PCAP_MAGIC      0xA1B2C3D4
#define LINKTYPE        1       // LINKTYPE_ETHERNET
struct packet_s
{
    uint32_t seconds;
    uint32_t useconds;
    uint32_t len;
    uint32_t clen;
};

#define ETH_ALEN        6
struct ethhdr                   // Ethernet header
{
    uint8_t h_dest[ETH_ALEN];
    uint8_t h_source[ETH_ALEN];
    uint16_t h_proto;
};
#define ETH_P_IPV6      0x86DD

struct ip6_hdr                  // IPv6 header
{
    union
    {
        struct ip6_hdrctl
        {
            uint32_t ip6_un1_flow;
            uint16_t ip6_un1_plen;
            uint8_t  ip6_un1_nxt;
            uint8_t  ip6_un1_hlim;
        } ip6_un1;
        uint8_t ip6_un2_vfc;
    } ip6_ctlun;
    struct in6_addr ip6_src;
    struct in6_addr ip6_dst;
};
#define ip6_flow  ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen  ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt   ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim  ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops  ip6_ctlun.ip6_un1.ip6_un1_hlim

struct tcphdr                   // TCP header
{
    uint16_t th_sport;
    uint16_t th_dport;
    uint32_t th_seq;
    uint32_t th_ack;
    uint8_t th_x2:4;
    uint8_t th_off:4;
    uint8_t th_flags;
#define TH_FIN              0x01
#define TH_SYN              0x02
#define TH_RST              0x04
#define TH_PUSH             0x08
#define TH_ACK              0x10
#define TH_URG              0x20
    uint16_t th_win;       /* window */
    uint16_t th_sum;       /* checksum */
    uint16_t th_urp;       /* urgent pointer */
};

/*
 * Calculate the TCP checksum.
 */
static uint32_t tcp_checksum_get(const uint8_t *buf, ssize_t size, ssize_t i)
{
    uint32_t x = 0;
    x |= (i < 0 || i >= size? 0x00: buf[i]);
    i++;
    x |= (uint32_t)(i < 0 || i >= size? 0x00: buf[i]) << 8;
    return x;
}
static uint16_t tcp_checksum(const struct ip6_hdr *ip6_hdr,
    const struct tcphdr *tcp, const uint8_t *payload, size_t len)
{
    struct pseudohdr
    {
        struct in6_addr src;
        struct in6_addr dst;
        uint32_t len;
        uint8_t zero[3];
        uint8_t nxt;
    } phdr;

    memcpy(&phdr.src, &ip6_hdr->ip6_src, sizeof(struct in6_addr));
    memcpy(&phdr.dst, &ip6_hdr->ip6_dst, sizeof(struct in6_addr));
    phdr.len = htonl(len + sizeof(*tcp));
    memset(phdr.zero, 0, sizeof(phdr.zero));
    phdr.nxt = IPPROTO_TCP;

    uint32_t sum = 0;
    const uint8_t *buf = (const uint8_t *)&phdr;
    for (size_t i = 0; i < sizeof(phdr); i += 2)
        sum += tcp_checksum_get(buf, sizeof(phdr), i);
    buf = (const uint8_t *)tcp;
    for (size_t i = 0; i < sizeof(*tcp); i += 2)
        sum += tcp_checksum_get(buf, sizeof(*tcp), i);
    for (size_t i = 0; i < len; i += 2)
        sum += tcp_checksum_get(payload, len, i);
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

/*
 * Calculate the FCS checksum.
 */
static uint32_t fcs_checksum(uint32_t fcs, const void *buf0, size_t len)
{
    const uint8_t *buf = (const uint8_t *)buf0;
    uint32_t polynomial = 0xedb88320;
    size_t i, j;

    for (i = 0; i < len; i++)
    {
        fcs ^= buf[i];
        for (j = 0; j < 8; j++)
        {
            if (fcs & 0x00000001)
                fcs = (fcs >> 1) ^ polynomial;
            else
                fcs >>= 1;
        }
    }
    return fcs;
}

/*
 * Initialize protocol headers.
 */
static size_t init_hdrs(struct ethhdr *ether, struct ip6_hdr *ip6,
    struct tcphdr *tcp, uint8_t flags, const uint8_t *buf, size_t len,
    uint32_t *fcsp, ENTRY *E, bool outbound)
{
    ether->h_proto = htons(ETH_P_IPV6);
    const char *src = "SSSSSSSSSSSSSSSS", *dst = "DDDDDDDDDDDDDDDD";
    memcpy(ether->h_source, (outbound? src: dst), ETH_ALEN);
    memcpy(ether->h_dest,   (outbound? dst: src), ETH_ALEN);

    size_t mtu = UINT16_MAX - 1024;
    size_t rem = (len > mtu? len - mtu: 0);
    len = (len > mtu? mtu: len);

    uint16_t len16 = (uint16_t)len + sizeof(*tcp);
    memset(ip6, 0x0, sizeof(ip6));
    ip6->ip6_flow = htonl(0x60000000);
    ip6->ip6_plen = htons(len16);
    ip6->ip6_nxt  = IPPROTO_TCP;
    ip6->ip6_hops = 255;
    memcpy(&ip6->ip6_src, (outbound? src: dst), sizeof(ip6->ip6_src));
    memcpy(&ip6->ip6_dst, (outbound? dst: src), sizeof(ip6->ip6_dst));

    memset(tcp, 0x0, sizeof(*tcp));
    uint16_t dst16 = htons((uint16_t)E->port);
    const char *dst8 = (char *)&dst16;
    memcpy(&tcp->th_sport, (outbound? src: dst8), sizeof(tcp->th_sport));
    memcpy(&tcp->th_dport, (outbound? dst8: src), sizeof(tcp->th_dport));
    tcp->th_seq   = htonl(outbound? E->seq: E->ack);
    tcp->th_ack   = htonl(outbound? E->ack: E->seq);
    tcp->th_off   = sizeof(*tcp) / sizeof(uint32_t);
    tcp->th_flags = flags & ~(rem > 0? TH_PUSH: 0);
    tcp->th_win   = htons(UINT16_MAX);
    tcp->th_sum   = tcp_checksum(ip6, tcp, buf, len);

    uint32_t fcs = 0xffffffff;
    fcs = fcs_checksum(fcs, ether, sizeof(*ether));
    fcs = fcs_checksum(fcs, ip6, sizeof(*ip6));
    fcs = fcs_checksum(fcs, tcp, sizeof(*tcp));
    fcs = fcs_checksum(fcs, buf, len);
    *fcsp = ~fcs;

    return len;
}

/*
 * Write a packet to the PCAP file.
 */
static void pcap_write_packet(FILE *pcap, struct ethhdr *ether,
    struct ip6_hdr *ip6, struct tcphdr *tcp, const uint8_t *buf, size_t len,
    uint32_t fcs)
{
    static uint64_t record_time = 0;
    if (record_time == 0)
        record_time = get_time();
    struct packet_s pkt = {0};
    uint64_t T = get_time() - record_time;
    pkt.seconds  = (uint32_t)(T / 1000000);
    pkt.useconds = (uint32_t)(T % 1000000);
    pkt.len = pkt.clen = sizeof(*ether) + sizeof(*ip6) + sizeof(*tcp)
        + len + sizeof(fcs);
    if (fwrite(&pkt, sizeof(pkt), 1, pcap) != 1)
        error("failed to write packet PCAP header: %s", strerror(errno));
    if (fwrite(ether, sizeof(*ether), 1, pcap) != 1)
        error("failed to write packet ethernet header: %s", strerror(errno));
    if (fwrite(ip6, sizeof(*ip6), 1, pcap) != 1)
        error("failed to write packet IPv6 header: %s", strerror(errno));
    if (fwrite(tcp, sizeof(*tcp), 1, pcap) != 1)
        error("failed to write packet TCP header: %s", strerror(errno));
    if (fwrite(buf, sizeof(uint8_t), len, pcap) != len)
        error("failed to write packet data: %s", strerror(errno));
    if (fwrite(&fcs, sizeof(fcs), 1, pcap) != 1)
        error("failed to write packet FCS: %s", strerror(errno));
    fflush(pcap);
}

/*
 * Write an "open" event to a PCAP file.
 */
static void pcap_write_open(FILE *pcap, int fd)
{
    struct ethhdr ether;
    struct ip6_hdr ip6;
    struct tcphdr tcp;
    uint32_t fcs;

    ENTRY *E = fd_entry(fd);
    if (E == NULL)
        return;

    init_hdrs(&ether, &ip6, &tcp, TH_SYN, NULL, 0, &fcs, E, OUTBOUND);
    pcap_write_packet(pcap, &ether, &ip6, &tcp, NULL, 0, fcs);

    E->seq++;
    init_hdrs(&ether, &ip6, &tcp, TH_SYN | TH_ACK, NULL, 0, &fcs, E, INBOUND);
    pcap_write_packet(pcap, &ether, &ip6, &tcp, NULL, 0, fcs);

    E->ack++;
    init_hdrs(&ether, &ip6, &tcp, TH_ACK, NULL, 0, &fcs, E, OUTBOUND);
    pcap_write_packet(pcap, &ether, &ip6, &tcp, NULL, 0, fcs);
}

/*
 * Write a "close" event to a PCAP file.
 */
static void pcap_write_close(FILE *pcap, int fd)
{
    struct ethhdr ether;
    struct ip6_hdr ip6;
    struct tcphdr tcp;
    uint32_t fcs;

    ENTRY *E = fd_entry(fd);
    if (E == NULL)
        return;

    init_hdrs(&ether, &ip6, &tcp, TH_FIN | TH_ACK, NULL, 0, &fcs, E, OUTBOUND);
    pcap_write_packet(pcap, &ether, &ip6, &tcp, NULL, 0, fcs);

    init_hdrs(&ether, &ip6, &tcp, TH_FIN | TH_ACK, NULL, 0, &fcs, E, INBOUND);
    pcap_write_packet(pcap, &ether, &ip6, &tcp, NULL, 0, fcs);
}

/*
 * Write an iov to a PCAP file.
 */
static void pcap_write(FILE *pcap, const struct iovec *iov, size_t iovcnt,
    size_t max, int fd, bool outbound)
{
    ENTRY *E = fd_get(fd);
    if (E == NULL)
        return;
    size_t len = 0;
    for (size_t i = 0; i < iovcnt && len < max; i++)
        len += iov[i].iov_len;
    len = (len > max? max: len);
    uint8_t *buf = iov_flatten(iov, iovcnt, len);
    uint8_t *payload = buf;

    struct ethhdr ether;
    struct ip6_hdr ip6;
    struct tcphdr tcp;
    uint32_t fcs;

    bool once = true;
    while (len > 0 || once)
    {
        size_t r = init_hdrs(&ether, &ip6, &tcp, TH_PUSH | TH_ACK | TH_URG,
            payload, len, &fcs, E, outbound);
        pcap_write_packet(pcap, &ether, &ip6, &tcp, payload, r, fcs);

        E->seq += (outbound? (uint32_t)r: 0);
        E->ack += (outbound? 0: (uint32_t)r);

        payload += r;
        len     -= r;
        once     = false;
    }

    init_hdrs(&ether, &ip6, &tcp, TH_ACK, NULL, 0, &fcs, E, !outbound);
    pcap_write_packet(pcap, &ether, &ip6, &tcp, NULL, 0, fcs);

    free(buf);
}

/*
 * Write a buffer to a PCAP file.
 */
static void pcap_write(FILE *pcap, const uint8_t *buf, ssize_t len, int fd,
    bool outbound)
{
    struct iovec iov;
    iov.iov_base = (void *)buf;
    iov.iov_len  = len;
    pcap_write(pcap, &iov, 1, SIZE_MAX, fd, outbound);
}

/*
 * Read a message from a PCAP file.
 */
static MSG *pcap_read(FILE *pcap, const char *filename, uint32_t *pkt_id,
    uint32_t *msg_id)
{
    *msg_id  = *msg_id + 1;
    MSG *msg = NULL;
    uint32_t space = 0, extra = UINT16_MAX+1;
    bool push = false;
    while (!push)
    {
        struct packet_s pkt;
        if (fread(&pkt, sizeof(pkt), 1, pcap) != 1)
        {
            if (ferror(pcap))
                error("failed to read message header from \"%s\": %s",
                    filename, strerror(errno));
            if (msg == NULL)
                return NULL;
            error("failed to read message header from \"%s\"; "
                "unexpected eof-of-file", filename);
        }
        if (pkt.len != pkt.clen)
            error("failed to read truncated message data from \"%s\"",
                filename);
        if (pkt.len < sizeof(struct ethhdr) + sizeof(struct ip6_hdr) +
                sizeof(struct tcphdr))
            error("failed to parse packet (#%u) from \"%s\"; packet "
                "length %u is too small", *pkt_id, filename, pkt.len);
        *pkt_id = *pkt_id + 1;

        // Parse the packet:
        uint8_t hdrs[sizeof(struct ethhdr) + sizeof(struct ip6_hdr) +
            sizeof(struct tcphdr)];
        if (fread(hdrs, sizeof(hdrs), 1, pcap) != 1)
            error("failed to read packet header from \"%s\": %s",
                filename, strerror(errno));
        const char *src = "SSSSSSSSSSSSSSSS", *dst = "DDDDDDDDDDDDDDDD";
        const struct ethhdr *ether = (struct ethhdr *)hdrs;
        const struct ip6_hdr *ip6  = (struct ip6_hdr *)(ether + 1);
        if (ntohs(ether->h_proto) != ETH_P_IPV6)
            error("failed to parse packet (#%u) from \"%s\"; expected "
                "IPv6 ethernet type (0x%.4X), found (%.4X)", *pkt_id,
                filename, ETH_P_IPV6, ntohs(ether->h_proto));
        bool outbound = false;
        if (memcmp(ether->h_source, src, ETH_ALEN) == 0 &&
            memcmp(ether->h_dest, dst, ETH_ALEN) == 0)
            outbound = true;
        else if (memcmp(ether->h_source, dst, ETH_ALEN) == 0 &&
                 memcmp(ether->h_dest, src, ETH_ALEN) == 0)
            outbound = false;
        else
            error("failed to parse packet (#%u) from \"%s\"; expected "
                "source/destination ethernet address "
                "(%.1X:%.1X:%.1X:%.1X:%.1X:%.1X or "
                "%.1X:%.1X:%.1X:%.1X:%.1X:%.1X), found "
                "(%.1X:%.1X:%.1X:%.1X:%.1X:%.1X and "
                "%.1X:%.1X:%.1X:%.1X:%.1X:%.1X)",
                *pkt_id, filename,
                src[0], src[1], src[2], src[3], src[4], src[5],
                dst[0], dst[1], dst[2], dst[3], dst[4], dst[5],
                ether->h_source[0], ether->h_source[1], ether->h_source[2],
                ether->h_source[3], ether->h_source[4], ether->h_source[5],
                ether->h_dest[0], ether->h_dest[1], ether->h_dest[2],
                ether->h_dest[3], ether->h_dest[4], ether->h_dest[5]);
        // The packet is likely valid -> less specific error messages:
        if (ntohl(ip6->ip6_flow) != 0x60000000 || ip6->ip6_hops == 0 ||
                memcmp(&ip6->ip6_src, (outbound? src: dst),
                    sizeof(ip6->ip6_src)) != 0 ||
                memcmp(&ip6->ip6_dst, (outbound? dst: src),
                    sizeof(ip6->ip6_dst)) != 0)
            error("failed to parse packet (#%u) from \"%s\": invalid IPv6 "
                "header", *pkt_id, filename);
        if (ip6->ip6_nxt != IPPROTO_TCP)
            error("failed to parse packet (#%u) from \"%s\": missing TCP "
                "header", *pkt_id, filename);
        const struct tcphdr *tcp;
        uint32_t len = ntohs(ip6->ip6_plen);
        tcp = (struct tcphdr *)(ip6 + 1);
        uint32_t exp_len = pkt.len - sizeof(struct ethhdr) -
            sizeof(struct ip6_hdr) - sizeof(uint32_t);
        if (len < sizeof(struct tcphdr) || len != exp_len)
            error("failed to parse packet (#%u) from \"%s\": invalid "
                "packet length; expected %u, got %u", *pkt_id, filename,
                exp_len, len);
        uint16_t dst16 = (outbound? tcp->th_dport: tcp->th_sport);
        const char *dst8 = (char *)&dst16;
        if (memcmp(&tcp->th_sport, (outbound? src: dst8),
                sizeof(tcp->th_sport)) != 0 ||
            memcmp(&tcp->th_dport, (outbound? dst8: src),
                sizeof(tcp->th_dport)) != 0)
            error("failed to parse packet (#%u) from \"%s\": invalid TCP "
                "header", *pkt_id, filename);
        int port = (int)ntohs(dst16);
        if (msg != NULL && (msg->outbound != outbound || msg->port != port))
            error("failed to parse packet (#%u) from \"%s\": invalid packet "
                "sequence", *pkt_id, filename);
        len -= sizeof(struct tcphdr);
        uint32_t fcs = 0;
        uint8_t *data = NULL;
        if (len > 0)
        {
            push = ((tcp->th_flags & TH_PUSH) != 0);
            if (msg == NULL || len > space)
            {
                space  = (push? 0: extra);
                extra += space;
                uint32_t mlen = (msg == NULL? 0: msg->len);
                msg = (MSG *)xrealloc(msg,
                    sizeof(MSG) + mlen + len + space);
                msg->prev     = msg->next = NULL;
                msg->id       = *msg_id;
                msg->port     = port;
                msg->outbound = outbound;
                msg->len      = mlen;
            }
            else
                space -= len;
            data = msg->payload + msg->len;
            if (fread(data, len, 1, pcap) != 1)
                error("failed to read packet data from \"%s\": %s",
                    filename, strerror(errno));
            msg->len += len;
            fcs = *(uint32_t *)(msg->payload + msg->len);
        }
        if (fread(&fcs, sizeof(fcs), 1, pcap) != 1)
            error("failed to read packet data from \"%s\": %s",
                filename, strerror(errno));
        if (option_validate)
        {
            struct tcphdr tcp2;
            memcpy(&tcp2, tcp, sizeof(tcp2));
            tcp2.th_sum = 0x0;
            tcp2.th_sum = tcp_checksum(ip6, &tcp2, data, len);
            if (tcp2.th_sum != tcp->th_sum)
                error("failed to parse packet (#%u) from \"%s\": invalid TCP "
                    "checksum", *pkt_id, filename);
            uint32_t fcs2 = 0xffffffff;
            fcs2 = fcs_checksum(fcs2, hdrs, sizeof(hdrs));
            fcs2 = fcs_checksum(fcs2, data, len);
            fcs2 = ~fcs2;
            if (fcs2 != fcs)
                error("failed to parse packet (#%u) from \"%s\": invalid FCS "
                    "checksum", *pkt_id, filename);
        }
        if (len == 0 && (tcp->th_flags & TH_URG) == 0 && msg != NULL)
            error("failed to parse packet (#%u) from \"%s\": invalid "
                "packet sequence", *pkt_id, filename);
    }
    assert(msg != NULL);
    if (space > 0)
        msg = (MSG *)xrealloc(msg, sizeof(MSG) + msg->len);
    return msg;
}

/*
 * Parse a PCAP file.
 */
static size_t pcap_parse(FILE *pcap, const char *filename, QUEUE *Q)
{
    uint32_t pkt_id = 0, msg_id = 0, call_id = 0;
    while (MSG *M = pcap_read(pcap, filename, &pkt_id, &msg_id))
    {
        if (M->port == SCHED_PORT)
        {
            call_id++;
            if (M->len < sizeof(SYSCALL))
                error("failed to parse syscall (#%u) from \"%s\"; invalid "
                    "record size", call_id, filename);
            SCHED *R = (SCHED *)xmalloc(sizeof(SCHED) + M->len);
            memcpy(R->data, M->payload, M->len);
            R->len  = M->len;
            R->next = option_SCHED;
            option_SCHED = R;
            xfree(M);
        }
        else
            queue_push_back(Q, M);
    }
    SCHED *prev = NULL, *next = NULL;
    for (SCHED *curr = option_SCHED; curr != NULL; curr = next)
    {
        next = curr->next;
        curr->next = prev;
        option_SCHED = prev = curr;
    }
    return msg_id+1;
}

/*
 * Open a PCAP file.
 */
static FILE *pcap_open(const char *filename, char mode)
{
    // PCAP_FILENO is passed in from the wrapper
    struct pcap_s pcap;
    FILE *stream = NULL;
    switch (mode)
    {
        case 'r':
            stream = fdopen(PCAP_FILENO, "r");
            if (fread(&pcap, sizeof(pcap), 1, stream) != 1)
                error("failed to read PCAP header from \"%s\": %s", filename,
                    strerror(errno));
            if (pcap.magic != PCAP_MAGIC ||
                    pcap.major != 2 || pcap.minor != 4 ||
                    pcap.snaplen != INT32_MAX ||
                    pcap.linktype != LINKTYPE)
                error("failed to parse PCAP header from \"%s\"", filename);
            break;
        case 'w':
            stream = fdopen(PCAP_FILENO, "w");
            if (stream == NULL)
                error("failed to open \"%s\" for writing: %s", filename,
                    strerror(errno));
            memset(&pcap, 0x0, sizeof(pcap));
            pcap.magic    = PCAP_MAGIC;
            pcap.major    = 2;
            pcap.minor    = 4;
            pcap.snaplen  = INT32_MAX;
            pcap.linktype = LINKTYPE;
            if (fwrite(&pcap, sizeof(pcap), 1, stream) != 1)
                error("failed to write PCAP header to \"%s\": %s", filename,
                    strerror(errno));
            break;
        default:
            assert(mode == 'r' || mode == 'w');
    }
    return stream;
}

