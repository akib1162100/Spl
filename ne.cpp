#include <bits/stdc++.h>
#include <sys/socket.h>
#include <stdio.h> 
#include <stdlib.h> //for exit(0);
#include <errno.h> //For errno - the error number
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h> 



using namespace std;

#define htons(n)

struct globalHeader {

    unsigned char magic [4];
    unsigned char major [2];
    unsigned char mainor [2];
    unsigned char timeZone [8];
    unsigned char snapLength [4];
    unsigned char linkHeaderType[4];

}; // 24 bytes


FILE *iFile;
int sock_raw;


void printGlobalheader ()
{
	long long int magic = 2712847316; 
    long long int majorV = 2;
    long long int minorV = 4;
    long long int timeZone = 0;
    long long int snapLength = 65535;
    long long int linkLayerHedrType = 1;


    fwrite(&magic,4,1,iFile);
    fwrite(&majorV,2,1,iFile);
    fwrite(&minorV,2,1,iFile);
    fwrite(&timeZone,8,1,iFile);
    fwrite(&snapLength,4,1,iFile);
    fwrite(&linkLayerHedrType,4,1,iFile);

}



void printPacket(int data_size)
{
    long long int epochTime = 0;
    long long int captureTime = 0;
    long long int packetSize = data_size;
    long long int packetLength = data_size;
    
    
    fwrite(&epochTime,4,1,iFile);
    fwrite(&captureTime,4,1,iFile);
    fwrite(&packetSize,4,1,iFile);
    fwrite(&packetLength,4,1,iFile);




}






int main()
{
	int co=0;
	int saddr_size , data_size;
    struct sockaddr saddr;                  
    
    unsigned char buffer[100000];  

	iFile=fopen("a.pcap","wb");

	sock_raw = socket( AF_PACKET , SOCK_RAW ,htons(ETH_P_ALL)) ;

	if(sock_raw < 0)//return negetive value if socket doesnot create properly
    {
        cout<<"Failed to create socket"<<endl;
        return 0;
    }


    printGlobalheader ();
	   
       while(1)
	    {
	    	data_size = recvfrom(sock_raw , buffer ,  100000, 0 , &saddr , (socklen_t*)&saddr_size);

            
	    	if(data_size <0 )
        {
            printf("\tSomething Error, failed to get packets\n");
        }

        printPacket(data_size);
        
        fwrite(&buffer,sizeof(unsigned char )*data_size,1,iFile);
        co++;



	    }



	}