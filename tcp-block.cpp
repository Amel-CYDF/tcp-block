#include <libnet.h>
#include <pcap.h>
#include <string>
#include <thread>
#define SWAP(X,Y) {auto T=X; X=Y; Y=T;}
using eth_hdr = struct libnet_ethernet_hdr;
using ip_hdr = struct libnet_ipv4_hdr;
using tcp_hdr = struct libnet_tcp_hdr;

#pragma pack(push, 1)
struct packet {
	eth_hdr eth;
	ip_hdr ip;
	tcp_hdr tcp;
	char data[64]="HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n";
};
#pragma pack(pop)

void usage()
{
	printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
	exit(1);
}

void getmymac(char *dev, uint8_t mac[]) {
	struct ifreq s;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0) {
		printf("Failed to make mac socket\n");
		exit(1);
	}

	strncpy(s.ifr_name, dev, IFNAMSIZ);
	if(ioctl(fd, SIOCGIFHWADDR, &s) < 0) {
		printf("Failed to get MAC\n");
		exit(1);
	}

	memcpy(mac, s.ifr_hwaddr.sa_data, 6);
	close(fd);
}

bool ispattern(char *s, char *p, uint16_t len) {
	uint16_t plen = strlen(p);
	if(len < plen) return false;
	for(auto i = len - plen + 1; i--; )
		if(strncmp(s + i, p, plen) == 0)
			return true;
	return false;
}

uint16_t sum(uint16_t *p, uint32_t ret, uint16_t len) {
	for(auto i = len / 2; i--; p++) {
		ret += ntohs(*p);
	}
	if(len&1) ret += ntohs(*p & 0x00ff);
	ret = (ret >> 16) + (ret & 0xffff);
	ret += (ret >> 16);
	return (uint16_t)ret;
}

void makepacket(packet *pk, uint16_t len, uint8_t mac[], bool isfw) {
	if(!isfw) SWAP(pk -> tcp.th_sport, pk -> tcp.th_dport)
	pk -> tcp.th_seq = htonl(ntohl(pk -> tcp.th_seq) + len);
	if(!isfw) SWAP(pk -> tcp.th_seq, pk -> tcp.th_ack)
	pk -> tcp.th_off = sizeof(tcp_hdr) / 4;
	pk -> tcp.th_flags = TH_ACK;
	if(isfw) pk -> tcp.th_flags |= TH_RST;
	else pk -> tcp.th_flags |= TH_FIN;

	pk -> ip.ip_len = htons((uint16_t)sizeof(ip_hdr) + sizeof(tcp_hdr) + (isfw ? 0 : strlen(pk -> data)));
	pk -> ip.ip_ttl = 128;
	if(!isfw) SWAP(pk -> ip.ip_src, pk -> ip.ip_dst)

	if(!isfw) memcpy(pk -> eth.ether_dhost, pk -> eth.ether_shost, 6);
	for(int i=6; i--;)
		pk -> eth.ether_shost[i] = mac[i];

	pk -> ip.ip_sum = 0;
	pk -> ip.ip_sum = htons(~sum((uint16_t *)&(pk -> ip), 0, sizeof(ip_hdr)));

	pk -> tcp.th_sum = 0;
	uint32_t tmp = pk -> ip.ip_p;
	tmp += ntohs(pk -> ip.ip_len) - sizeof(ip_hdr);
	tmp = sum((uint16_t *)&(pk -> ip.ip_src), tmp, 8);
	pk -> tcp.th_sum = htons(~sum((uint16_t *)&(pk -> tcp), tmp, ntohs(pk -> ip.ip_len) - sizeof(ip_hdr)));
}

int main(int argc, char *argv[]) {
	if(argc != 3)
		usage();

	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		exit(1);
	}
	
	uint8_t mymac[6];
	getmymac(dev, mymac);

	char *pat = argv[2];
	struct pcap_pkthdr *header;
	const u_char *recv;
	packet fw, bw;
	while(1) {
		int res = pcap_next_ex(pcap, &header, &recv);
		if(res == 0) continue;
		if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			pcap_close(pcap);
			exit(1);
		}

		eth_hdr *eth = (eth_hdr *)recv;
		if(ntohs(eth -> ether_type) != ETHERTYPE_IP) continue;

		ip_hdr *ip = (ip_hdr *)(recv + sizeof(eth_hdr));
		if(ip -> ip_p != IPPROTO_TCP) continue;

		tcp_hdr *tcp = (tcp_hdr *)((u_char *)ip + ip->ip_hl * 4);
		char *data = (char *)tcp + tcp->th_off * 4;
		uint16_t len = ntohs(ip->ip_len) - ip->ip_hl * 4 - tcp->th_off * 4;
		if(ispattern(data, pat, len) == false) continue;

		memcpy(&fw, recv, sizeof(eth_hdr) + sizeof(ip_hdr) + sizeof(tcp_hdr));
		memcpy(&bw, recv, sizeof(eth_hdr) + sizeof(ip_hdr) + sizeof(tcp_hdr));
		makepacket(&fw, len, mymac, 1);
		makepacket(&bw, len, mymac, 0);
		pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&fw), ntohs(fw.ip.ip_len) + sizeof(eth_hdr));
		pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&bw), ntohs(bw.ip.ip_len) + sizeof(eth_hdr));
	}
	pcap_close(pcap);
	return 0;
}
