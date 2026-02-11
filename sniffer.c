#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h> /* Includes net/ethernet.h */

/* * This function is called every time a packet is captured.
 * It formats the data into a clean CSV format for Python to read.
 */
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header;
    struct ip *ip_header;
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];

    // point to the Ethernet header (First 14 bytes)
    eth_header = (struct ether_header *) packet;

    // check if it's an IP packet (0x0800)
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        
        // 3. Jump past the Ethernet header to get the IP header
        ip_header = (struct ip *)(packet + ETHER_HDR_LEN);

        // convert IP addresses from binary to human-readable string
        inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

        // output as CSV: timestamp, src_ip, dst_ip, length
        // we use CSV so Python can split string by comma easily later.
        printf("%ld,%s,%s,%d\n", 
               pkthdr->ts.tv_sec, 
               source_ip, 
               dest_ip, 
               pkthdr->len);
        
        // flush stdout so Python receives data immediately, not in chunks
        fflush(stdout);
    }
}

int main(int argc, char *argv[]) {
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // 1. Find a device automatically
    device = "en0";
    if (device == NULL) {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }

    printf("Sniffing on device: %s\n", device);

    // 2. Open device for sniffing
    // Arguments: device, snaplen (65535), promiscuous (1), timeout (1000ms), error_buffer
    handle = pcap_open_live(device, 65535, 1, 1000, error_buffer);
    if (handle == NULL) {
        printf("Could not open device %s: %s\n", device, error_buffer);
        return 2;
    }

    // 3. Start the loop
    // -1 means loop forever. packet_handler is the function defined above.
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}