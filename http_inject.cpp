#include "pcap.h"

#pragma comment(lib,"ws2_32.lib")

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#else
#include <winsock.h>
#include <winsock2.h>
#include <WS2tcpip.h>

#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ETH_len 14
#define IP_len 20
#define TCP_len 20
#define TCP_payload ETH_len+IP_len+TCP_len

#define ETH_type 12
#define IP_prot 9

#define IP_chksum ETH_len+10
#define TCP_chksum ETH_len+IP_len+16

int TYPE_IPv4(const u_char* packet) {
	/******************************
		if type is IPv4: return 1
		else:			 return 0
	*******************************/
	return ((packet[ETH_type] == 0x08) && (packet[ETH_type+1] == 0x00));
}
int PROT_TCP(const u_char* packet) {
	/******************************
	if protocol is TCP: return 1
	else:				return 0
	*******************************/
	return (packet[ETH_len + IP_prot] == 0x06);
}

int check_GET(const u_char* packet, char* GET_check) {
	int i = 0;
	for (i = 0; i < 4; i++) {
		if (packet[TCP_payload + i] != GET_check[i])
			return 0;
	}
	return 1;
}

int calc_checksum_IP(u_char* packet) {
	unsigned short *c_packet = (unsigned short*)packet;
	unsigned checksum = 0;
	unsigned short finalchk;
	int i = 0;

	packet[IP_chksum] = 0x00;
	packet[IP_chksum + 1] = 0x00;

	for (i = 0; i < 10; i++) {
		checksum += c_packet[ETH_len/2 + i];
	}
	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >> 16);
	finalchk = (~checksum & 0xffff);

	packet[IP_chksum] = ((u_char*)&finalchk)[0];
	packet[IP_chksum + 1] = ((u_char*)&finalchk)[1];

	return 1;
}

int calc_checksum_TCP(u_char* packet, unsigned int len) {
	unsigned short *c_packet = (unsigned short*)packet;
	unsigned checksum = 0;
	unsigned short finalchk;
	int i = 0;

	packet[TCP_chksum] = 0x00;
	packet[TCP_chksum + 1] = 0x00;

	for (i = 0; i < 14; i++) {
		checksum += c_packet[(ETH_len + IP_len) / 2 + i];
	}
	for (i = 0; i < 4; i++) {
		checksum += c_packet[(ETH_len + 12) / 2 + i];
	}
	checksum += htons(0x0006);
	checksum += htons(0x001C);
	
	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >> 16);
	finalchk = (~checksum & 0xffff);
	packet[TCP_chksum] = ((u_char*)&finalchk)[0];
	packet[TCP_chksum + 1] = ((u_char*)&finalchk)[1];

	return 1;
}

int main(void) {
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	int res;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct tm ltime;
	char timestr[16];
	struct pcap_pkthdr *header;
	const u_char* pkt_data;
	u_char block_data[ETH_len + IP_len + TCP_len + 8];
	time_t local_tv_sec;
	FILE *fp;
	char GET_check[5] = "GET ";
	char tmp[5];

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	i = 0;
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	/*
	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);
	*/

	inum = 1;	// first device select

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* Open the device */
	if ((adhandle = pcap_open(d->name,          // name of the device
		65536,            // portion of the packet to capture. 
						  // 65536 guarantees that the whole packet will be captured on all the link layers
		PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
		1,             // read timeout
		NULL,             // authentication on the remote machine
		errbuf            // error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\n<<Checking Packet on %s...>>\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* Retrieve the packets */
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {

		if (res == 0)
			/* Timeout elapsed */
			continue;
		
		/* convert the timestamp to readable format */
/*		local_tv_sec = header->ts.tv_sec;
		localtime_s(&ltime, &local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

		printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
*/

		// suppose that packet is ethernet
		
		// check that type is IPv4
		if (!TYPE_IPv4(pkt_data)) {
			continue;
		}
		// check that protocol is TCP
		if (!PROT_TCP(pkt_data)) {
			continue;
		}

		// check HTTP traffic ( start with "GET " )
		if (check_GET(pkt_data,GET_check)) {
///*
			// forward fin
			for (i = 0; i < (ETH_len + IP_len)+4; i++) {
				block_data[i] = pkt_data[i];
			}
			block_data[ETH_len + 1] = 0x44;
			block_data[ETH_len + 2] = 0x00;
			block_data[ETH_len + 3] = 0x30;
			block_data[ETH_len + 4] = 0x77;
			block_data[ETH_len + 5] = 0xbf;
			calc_checksum_IP(block_data);
			// sequence
			*(unsigned int*)(&block_data[i]) = htonl(ntohl(*(unsigned int*)(&pkt_data[i])) + (header->caplen - (ETH_len + IP_len + TCP_len)));
			for (i = (ETH_len + IP_len + 8); i < (ETH_len + IP_len + 12); i++) {
				block_data[i] = pkt_data[i];
			}
			block_data[i++] = 0x50;
			block_data[i++] = 0x11;
			for (; i < (ETH_len + IP_len + 16); i++) {
				block_data[i] = pkt_data[i];
			}
			for (int j = 0; j < 4; j++) {
				block_data[i++] = 0x00;
			}
			block_data[i++] = 'b';
			block_data[i++] = 'l';
			block_data[i++] = 'o';
			block_data[i++] = 'c';
			block_data[i++] = 'k';
			block_data[i++] = 'e';
			block_data[i++] = 'd';
			block_data[i++] = '!';
			block_data[0x30] = 0x00;
			block_data[0x31] = 0x00;
			calc_checksum_TCP(block_data, i);

			if (pcap_sendpacket(adhandle, block_data, i) != 0) {
				printf("Error : Sending arp spoofing packet to victim !\n");
			}

//*/

			// backward fin
			for (i = 0; i < (ETH_len + IP_len) + 4; i++) {
				block_data[i] = pkt_data[i];
			}
				// ip change
			for (i = 0; i < 4; i++) {
				block_data[ETH_len + 12 + i] = pkt_data[ETH_len + 16 + i];
				block_data[ETH_len + 16 + i] = pkt_data[ETH_len + 12 + i];
			}
			block_data[ETH_len + 1] = 0x44;
			block_data[ETH_len + 2] = 0x00;
			block_data[ETH_len + 3] = 0x30;
			block_data[ETH_len + 4] = 0x77;
			block_data[ETH_len + 5] = 0xbf;
			calc_checksum_IP(block_data);
				// port change
			for (i = 0; i < 2; i++) {
				block_data[ETH_len + IP_len + i] = pkt_data[ETH_len + IP_len + 2 + i];
				block_data[ETH_len + IP_len + 2 + i] = pkt_data[ETH_len + IP_len + i];
			}
				// seq <-> ack change
			for (i = 0; i < 4; i++) {
				block_data[ETH_len + IP_len + 4 + i] = pkt_data[ETH_len + IP_len + 8 + i];
				block_data[ETH_len + IP_len + 8 + i] = pkt_data[ETH_len + IP_len + 4 + i];
			}
			i = (ETH_len + IP_len + 12);
			block_data[i++] = 0x50;
			block_data[i++] = 0x11;
			for (; i < (ETH_len + IP_len + 16); i++) {
				block_data[i] = pkt_data[i];
			}
			for (int j = 0; j < 4; j++) {
				block_data[i++] = 0x00;
			}
			block_data[i++] = 'b';
			block_data[i++] = 'l';
			block_data[i++] = 'o';
			block_data[i++] = 'c';
			block_data[i++] = 'k';
			block_data[i++] = 'e';
			block_data[i++] = 'd';
			block_data[i++] = '!';
			block_data[0x30] = 0x00;
			block_data[0x31] = 0x00;
			calc_checksum_TCP(block_data, i);

			if (pcap_sendpacket(adhandle, block_data, i) != 0) {
				printf("Error : Sending arp spoofing packet to victim !\n");
			}

			local_tv_sec = header->ts.tv_sec;
			localtime_s(&ltime, &local_tv_sec);
			strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

			printf("%s | HTTP blocked!\n", timestr);

		}
		else continue;
	}
	if (res == -1) {
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}


	return 0;
}