
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#define PROMISCUOUS 1

int main(void){

	char* device = NULL;//
	pcap_t* pcap_device;
	int i;
	int snaplen = 1000;
	char error_buf[PCAP_ERRBUF_SIZE];

	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int len,res;

	if(device == NULL){
		if( (device = pcap_lookupdev(error_buf)) == NULL){
			perror(error_buf);
			exit(-1);
		}
	}
	printf("%s Scanning\n", device);

	pcap_device = pcap_open_live(device, snaplen, PROMISCUOUS, 1000, error_buf);
	if (pcap_device == NULL){
		perror(error_buf);
		exit(-1);
	}

	while ((res = pcap_next_ex(pcap_device, &header, &pkt_data)) >= 0){

		if(res == 0)
			continue;
		len = 0;
		printf("Source Mac : ");
		printf("%02x",pkt_data[6]);
		for(i = 6; i < 12 ; i++){
			printf("%02x ", pkt_data[i]);
		}
		printf("\n");
		printf("Destination Mac : ");
		for( i = 0 ; i < 6 ; i++)
		{
			printf("%02x ", pkt_data[i]);
		}
		printf("\n");

		if( ntohs(*((unsigned short*)(&pkt_data[12]))) != 0x0800 ){
			printf("Type is not IPv4!\n");
			continue;
		}
		else{ 
			printf("Source IP : ");
			for(i=0;i<4;i++){
				printf("%d ",pkt_data[14+12+i]);
			}
			printf("\nDestination IP : ");
			for(i=0;i<4;i++){
				printf("%d ",pkt_data[14+16+i]);
			}
			printf("\n");

			// protocol check
			if( pkt_data[14+9] != 0x06 ){
				printf("Protocol is not TCP!\n\n");
				continue;
			}
			else{ // It's TCP !
				printf("     Source Port  %d\n",ntohs(*((unsigned short*)(&pkt_data[34]))));
				printf("Destination Port  %d\n\n",ntohs(*((unsigned short*)(&pkt_data[36]))));
			}

		}

	}

	if(res == -1){
		printf("Error reading the packets: %s\n", pcap_geterr(pd));
		return -1;
	}

	pcap_close(pcap_device);
	exit(0);

	return 0;
}
