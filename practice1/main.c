#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdint.h>
#include<errno.h>
#include<pcap.h>

#include<arpa/inet.h>
#include<netinet/ip_icmp.h>

#include"include/protos.h"

FILE *fp;


void process_icmp(const uint8_t *packet, int size) {
	struct icmphdr *icmp_hdr;

	icmp_hdr = (struct icmphdr *)packet;
	packet += sizeof(struct icmphdr);
	size -= sizeof(struct icmphdr);

	//printf("sizeof icmphdr: %lu\n", sizeof(struct icmphdr));
	if (icmp_hdr->type == ICMP_ECHOREPLY)
		fwrite(packet, size, 1, fp);

	return;
}


void process_ip(const uint8_t *packet, int size) {
	struct ip_hdr *ip_hdr;
	
	ip_hdr = (struct ip_hdr *)packet;
	packet += sizeof(struct ip_hdr);
	size -= sizeof(struct ip_hdr);
	
	switch(ip_hdr->proto) {//0?
		case IPPROTO_ICMP://1
		{
			printf("---ICMP---\n");
			process_icmp(packet, size);
			break;
		}
		case IPPROTO_TCP://6
		{
			printf("---TCP---\n");
			break;
		}
		case IPPROTO_UDP://17
		{
			printf("---UDP---\n");
			break;
		}
		default:
		{
			printf("no\n");
			break;
		}
	}

	return;
}


int main(int argc, char **argv) {
	if (argc  != 3) {
    fprintf(stderr, "Usage: ./icmpdata inputfile outputfile\n");
    exit(1);
  }

	pcap_t *p;
  char errbuf[PCAP_ERRBUF_SIZE];
	fp = fopen(argv[2], "wb");

  //p = pcap_open_offline(argv[1], errbuf);
  p = pcap_open_offline_with_tstamp_precision(argv[1], PCAP_TSTAMP_PRECISION_NANO, errbuf);

  if (!p){
    perror(argv[1]);
    exit(1);
  }

	uint16_t frame_num = 1;
	const uint8_t *packet;
	//memset(packet, 0, strlen(packet));
	struct pcap_pkthdr pkthdr;
	while ((packet = /*(uint8_t *)*/pcap_next(p, &pkthdr))/* != NULL*/){
		printf("*** frame%d ***\n", frame_num);
		printf("packet length: %d byte\n", pkthdr.caplen);
		
		struct ethernet_hdr *eth;
		int size = pkthdr.caplen;
		eth = (struct ethernet_hdr *) packet;
		/* increment */
		packet += sizeof(struct ethernet_hdr);
		size -= sizeof(struct ethernet_hdr);
		
		printf("---Ethernet---\n");
		
		uint16_t type_num = ntohs(eth->type);
		switch(type_num) {
			case ETHERTYPE_ARP:
			{
			  printf("---ARP---\n");
				break;
			}
			case ETHERTYPE_IP:
			{
				printf("---IP---\n");
				process_ip(packet, size);
				break;
			}
			case ETHERTYPE_IPV6:
			{
				printf("---IPv6---\n");
				break;
			}
			default:
			{
				printf("xxxxxxxxxx\n");
				break;
			}
		}
		
		printf("\n\n");
		frame_num++;
	}
	
	printf("fin\n");
	
	fclose(fp);
	pcap_close(p);

	return 0;
}
