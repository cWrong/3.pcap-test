#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <libnet/libnet-headers.h>
#include <arpa/inet.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

bool decapsulate(const u_char* packet){
	struct libnet_ethernet_hdr *eth = (struct libnet_ethernet_hdr *) packet;
	if(ntohs(eth->ether_type) != ETHERTYPE_IP)
		return false;

	u_char ETH_src[18];
	u_char ETH_dst[18];

	sprintf(ETH_src, "%02x:%02x:%02x:%02x:%02x:%02x", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
	sprintf(ETH_dst, "%02x:%02x:%02x:%02x:%02x:%02x", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

	struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
	if(ip->ip_p != 6)
		return false;

	u_char IP_src[16];
	u_char IP_dst[16];
	inet_ntop(AF_INET, &(ip->ip_src), IP_src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ip->ip_dst), IP_dst, INET_ADDRSTRLEN);

	struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + ip->ip_hl*4);
	printf("---------------Packet Info---------------\n");
	printf("[Ethernet] src mac: %s, dst mac: %s\n", ETH_src, ETH_dst);
	printf("[IP] src ip: %s, dst ip: %s\n", IP_src, IP_dst);
	printf("[TCP] src port: %d, dst port: %d\n", ntohs(tcp->th_sport), ntohs(tcp->th_dport));
	printf("[TCP] data: %8lx\n", (u_char*)tcp+tcp->th_off*4);
	printf("-------------------End-------------------\n\n");
	return true;

}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		decapsulate(packet);
	}

	pcap_close(pcap);
}
