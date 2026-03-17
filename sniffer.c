#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <signal.h>
#include <time.h>

static pcap_t *global_handle = NULL;
static unsigned long packet_count = 0;

/*
 * Clean shutdown on Ctrl-C
 */
void handle_sigint(int sig) {
    (void)sig;
    fprintf(stderr, "\n[Sniffer] Caught interrupt — captured %lu packets.\n", packet_count);
    if (global_handle) {
        pcap_breakloop(global_handle);
    }
}

/*
 * Extract TCP flag characters into a human-readable string.
 * Example output: "SA" for SYN+ACK, "F" for FIN, "R" for RST, etc.
 */
void tcp_flags_to_str(uint8_t flags, char *buf, size_t buflen) {
    size_t i = 0;
    memset(buf, 0, buflen);
    if (flags & TH_FIN)  { if (i < buflen - 1) buf[i++] = 'F'; }
    if (flags & TH_SYN)  { if (i < buflen - 1) buf[i++] = 'S'; }
    if (flags & TH_RST)  { if (i < buflen - 1) buf[i++] = 'R'; }
    if (flags & TH_PUSH) { if (i < buflen - 1) buf[i++] = 'P'; }
    if (flags & TH_ACK)  { if (i < buflen - 1) buf[i++] = 'A'; }
    if (flags & TH_URG)  { if (i < buflen - 1) buf[i++] = 'U'; }
    if (i == 0) {
        buf[0] = '-';
    }
}

/*
 * Called for every captured packet.
 * Outputs enriched CSV:
 *   timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, tcp_flags
 */
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    (void)user_data;

    struct ether_header *eth_header;
    struct ip *ip_header;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    const char *protocol = "OTHER";
    char flags_str[16] = "-";

    eth_header = (struct ether_header *)packet;

    /* Only process IP packets (0x0800) */
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }

    ip_header = (struct ip *)(packet + ETHER_HDR_LEN);

    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    unsigned int ip_header_len = ip_header->ip_hl * 4;

    switch (ip_header->ip_p) {
        case IPPROTO_TCP: {
            protocol = "TCP";
            struct tcphdr *tcp = (struct tcphdr *)((u_char *)ip_header + ip_header_len);
            src_port = ntohs(tcp->th_sport);
            dst_port = ntohs(tcp->th_dport);
            tcp_flags_to_str(tcp->th_flags, flags_str, sizeof(flags_str));
            break;
        }
        case IPPROTO_UDP: {
            protocol = "UDP";
            struct udphdr *udp = (struct udphdr *)((u_char *)ip_header + ip_header_len);
            src_port = ntohs(udp->uh_sport);
            dst_port = ntohs(udp->uh_dport);
            break;
        }
        case IPPROTO_ICMP: {
            protocol = "ICMP";
            /* ICMP has no ports; leave as 0 */
            break;
        }
        default:
            break;
    }

    /* CSV: timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, tcp_flags */
    printf("%ld,%s,%s,%u,%u,%s,%d,%s\n",
           pkthdr->ts.tv_sec,
           src_ip,
           dst_ip,
           src_port,
           dst_port,
           protocol,
           pkthdr->len,
           flags_str);

    fflush(stdout);
    packet_count++;
}

int main(int argc, char *argv[]) {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const char *device = "en0";

    /* Allow device override via command-line argument */
    if (argc >= 2) {
        device = argv[1];
    }

    signal(SIGINT, handle_sigint);

    fprintf(stderr, "[Sniffer] Aegis Packet Sniffer v2.0\n");
    fprintf(stderr, "[Sniffer] Sniffing on device: %s\n", device);
    fprintf(stderr, "[Sniffer] Output format: timestamp,src_ip,dst_ip,src_port,dst_port,protocol,length,tcp_flags\n");

    /* Open device: snaplen 65535, promiscuous mode, 1000ms timeout */
    handle = pcap_open_live(device, 65535, 1, 1000, error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "[Sniffer] Error: Could not open device %s: %s\n", device, error_buffer);
        return 1;
    }

    global_handle = handle;

    /* Print CSV header for downstream consumers */
    printf("timestamp,src_ip,dst_ip,src_port,dst_port,protocol,length,tcp_flags\n");
    fflush(stdout);

    /* Capture indefinitely */
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    fprintf(stderr, "[Sniffer] Shutdown complete. %lu packets captured.\n", packet_count);
    return 0;
}
