#include <bits/stdc++.h>
#include <sys/socket.h>
#include <stdio.h> 
#include <stdlib.h> 
#include <errno.h> 
#include <linux/types.h> 
#include <netinet/tcp.h>
#include <netinet/ip.h> 
#include <netinet/udp.h> 
#include <netinet/if_ether.h>
#include "analysis.h"
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

	unsigned char *buffer = (unsigned char *) malloc(65536);
	memset(buffer,0,65536);
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
	if((int)bufferArray[19]==27)
	{
		printf("this is from my protocol\nit says today is 30 may\n");

		bufferArray[19]=4;

	}



	fwrite(&bufferArray,sizeof(unsigned char )*buflen,1,iFile);
	printf("captured %d packet\n",i+1);


	}
}
	
