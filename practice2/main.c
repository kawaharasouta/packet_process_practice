#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<pcap.h>
#include<errno.h>
#include<arpa/inet.h>
#include<netinet/tcp.h>
#include"include/protos.h"

struct pcap_file_hdr {
  uint32_t magic_number;  /* magic number */
  uint16_t version_major; /* major version number */
  uint16_t version_minor; /* minor version number */
  int32_t  thiszone;      /* GMT to local correction */
  uint32_t sigfigs;       /* accuracy of timestamps */
  uint32_t snaplen;       /* max length of captured packets, in octets */
  uint32_t network;       /* data link type */
};

struct pcap_pkt_hdr {
  uint32_t ts_sec;   /* timestamp seconds */
  uint32_t ts_usec;  /* timestamp microseconds */
  uint32_t incl_len; /* number of octets of packet saved in file */
  uint32_t orig_len; /* actual length of packet */
};

void write_packet(FILE* fp, const void* pkt, size_t len) {
  struct pcap_pkt_hdr ph;
  ph.ts_sec = 0;
  ph.ts_usec = 0;
  ph.incl_len = len;
  ph.orig_len = len;
  fwrite(&ph, sizeof(ph), 1, fp);
  fwrite(pkt, len, 1, fp);
}

void write_filehdr(FILE* fp) {
  struct pcap_file_hdr fh;
  fh.magic_number = 0xa1b2c3d4;
  fh.version_major = 2;
  fh.version_minor = 4;
  fh.thiszone = 0;
  fh.sigfigs = 0;
  fh.snaplen = 65535;
  fh.network = 1;
  fwrite(&fh, sizeof(fh), 1, fp);
}

int main(int argc, char** argv) {
	if (argc != 2) {
		fprintf(stderr, "useage: ./main [filename]\n");
		exit(1);
	}

	pcap_t *p;
	char errbuf[PCAP_ERRBUF_SIZE];
	p = pcap_open_offline_with_tstamp_precision(argv[1], PCAP_TSTAMP_PRECISION_NANO, errbuf);
	if (!p){
		perror(argv[1]);
		exit(1);
	}

  FILE* fp_1 = fopen("rule1.pcap", "wb");
  FILE* fp_2 = fopen("rule2.pcap", "wb");
  FILE* fp_3 = fopen("rule3.pcap", "wb");

	/* file init */
  write_filehdr(fp_1);
  write_filehdr(fp_2);
  write_filehdr(fp_3);
	
	struct pcap_pkthdr pkthdr;
	const uint8_t *packet;
	uint8_t *packet_head; //to write
	int packet_len; //to write
	while ((packet = pcap_next(p, &pkthdr))) {
		packet_head = packet;
		struct ethernet_hdr *eth;
		int size = pkthdr.caplen;
		packet_len = size;
		eth = (struct ethernet_hdr *) packet;
		/* increment */
		packet += sizeof(struct ethernet_hdr);
		size -= sizeof(struct ethernet_hdr);
		uint16_t type_num = ntohs(eth->type);
		uint32_t target_src_addr = 0x8519a7e3; /*133.25.167.227*/
		uint32_t target_dest_addr = 0x85826b1a; /* 133.130.107.26 */
		if (type_num == ETHERTYPE_IP) {
			struct ip_hdr *iphdr;
			size -= sizeof(struct ip_hdr);
			iphdr = packet;
			packet += sizeof(struct ip_hdr);
			if (ntohl(iphdr->dest_addr) == target_dest_addr) {
				if (ntohl(iphdr->src_addr) == target_src_addr) {
					if (iphdr->proto == 6) {
						struct tcphdr *tcphdr = packet;
						if (ntohs(tcphdr->th_dport) == 22) {
							write_packet(fp_1, packet_head, packet_len);
						}
					}
				}
				if (iphdr->proto == 6) {
					struct tcphdr *tcphdr = packet;
					if (ntohs(tcphdr->th_dport) == 22) {
						write_packet(fp_2, packet_head, packet_len);
					}
					if (ntohs(tcphdr->th_dport) == 80) {
						write_packet(fp_3, packet_head, packet_len);
					}
				}
			}
		}
	}

  //write_packet(fp, pkt1, sizeof(pkt1));
  //write_packet(fp, pkt2, sizeof(pkt2));
  fclose(fp_1);
  fclose(fp_2);
  fclose(fp_3);
	return 0;
}
