#include <bits/stdc++.h>
#include <sys/socket.h>
#include <stdio.h> 
#include <stdlib.h> //for exit(0);
#include <errno.h> //For errno - the error number
#include <linux/types.h> 
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h> 
#include <netinet/udp.h> 
#include <netinet/if_ether.h>

using namespace std;


#if BYTE_ORDER == BIG_ENDIAN
#define htons(n)
#else 
#define htons(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))
#endif ///converting host byte order..

//FILE *iFile;
int sock_r;
struct sockaddr_in source,dest;

void addPacketHeaderInFile(int data_size , FILE *packetCapture){
    
    unsigned long int epochTime = 1520144305;
    unsigned long int captureTime = 479050000;
    unsigned long int packetSize = data_size;
    unsigned long int packetLength = data_size;    
    
    fwrite(&epochTime,4,1,packetCapture);
    fwrite(&captureTime,4,1,packetCapture);
    fwrite(&packetSize,4,1,packetCapture);
    fwrite(&packetLength,4,1,packetCapture);
}


void addPcapGlobalHeaderInFile(FILE *packetCapture){
   
    unsigned long int magicNumber = 2712847316; 
    unsigned short int majorVersion = 2;
    unsigned short int minorVersion = 4;
    unsigned long int timeZone = 0;
    unsigned long int sigfigs = 0;
    unsigned long int lengthOfCapturePackets = 65535;
    unsigned long int linkLayerHedrType = 1;
        
    fwrite(&magicNumber,4,1,packetCapture);
    fwrite(&majorVersion,2,1,packetCapture);
    fwrite(&minorVersion,2,1,packetCapture);
    fwrite(&timezone,4,1,packetCapture);
    fwrite(&sigfigs,4,1,packetCapture);
    fwrite(&lengthOfCapturePackets,4,1,packetCapture);
    fwrite(&linkLayerHedrType,4,1,packetCapture);
        
}






int main()
{
	
	sock_r=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	if(sock_r<0)
	{
	printf("error in socket\n");
	return -1;
	}
	FILE *iFile;

	iFile=fopen("a.pcap","wb");
	addPcapGlobalHeaderInFile(iFile);
	unsigned char bufferArray[10000];

	//unsigned char *buffer = (unsigned char *) malloc(65536);
	//memset(buffer,0,65536);
	struct sockaddr saddr;
	int saddr_len = sizeof (saddr);
	int buflen;
	 
	 for(int i=0;i<100;i++)
	 {
	
		buflen=recvfrom(sock_r,bufferArray,65536,0,&saddr,(socklen_t *)&saddr_len);
		if(buflen<0)
		{
		printf("error in reading recvfrom function\n");
		return -1;
	 	}
	
	addPacketHeaderInFile(buflen,iFile);

	fwrite(&bufferArray,sizeof(unsigned char )*buflen,1,iFile);





	/*
	struct ethhdr *eth = (struct ethhdr *)(buffer);
	printf("\nEthernet Header\n");
	printf("\t|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
	printf("\t|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
	printf("\t|-Protocol : %d\n",eth->h_proto);

	unsigned short iphdrlen;
	struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = ip->daddr;


	printf("Version : %d\n",(unsigned int)ip->version);
	printf("Internet Header Length : %d \n",(unsigned int)ip->ihl,((unsigned int)(ip->ihl))*4 );
	printf("Type Of Service : %d\n",(unsigned int)ip->tos );
	printf("Total Length : %d Bytes\n",ntohs(ip->tot_len) );
*/

	}
	

}