#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

// Pseudo checksum function
unsigned short csum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    short answer;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char*)&oddbyte) = *(unsigned char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;

    return answer;
}

int main() {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock == -1) {
        perror("Socket");
        return 1;
    }

    // Allow socket to build headers
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        return 1;
    }

    char packet[4096];
    memset(packet, 0, 4096);

    // IP header
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(8080);
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Covert value (4 bytes)
    uint32_t covert_seq = 0xDEADBEEF;

    // Selector stored in TCP Offset (header length field)
    uint8_t selector = 2;  // choose 0–3 (which byte of the sequence to send)

    if (selector > 3) {
        fprintf(stderr, "Invalid selector (must be 0–3)\n");
        return 1;
    }

    // Extract the selected byte
    uint8_t selected_byte = (covert_seq >> (8 * (3 - selector))) & 0xFF;

    // Build IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr("127.0.0.1");
    iph->daddr = sin.sin_addr.s_addr;
    iph->check = csum((unsigned short *)packet, iph->tot_len >> 1);

    // Build TCP Header
    tcph->source = htons(12345);
    tcph->dest = htons(8080);
    
    // Place selected byte in sequence field (rest is zeroed for simplicity)
    tcph->seq = htonl((uint32_t)selected_byte);

    tcph->ack_seq = 0;
    tcph->res1 = 0;
    tcph->doff = selector + 5; // Must be ≥5. Add selector for covert signal.
    tcph->syn = 1;
    tcph->window = htons(5840);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    // Send the packet
    if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto");
    } else {
        printf("Packet sent with selector=%u, byte=0x%02X\n", selector, selected_byte);
    }

    close(sock);
    return 0;
}
