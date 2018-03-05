#include<bits/stdc++.h>
#include<stdio.h>
#include <stdlib.h>

using namespace std;



struct globalHeader {

    char magic [4];
    char major [2];
    char mainor [2];
    char timeZone [8];
    char snapLength [4];
    char linkHeaderType[4];

}; // 24 bytes

struct packetHeader
{
    char timeStamp[4];
    char packetCapTime[4];
    unsigned  char packetSize[4];
    unsigned char packetLength[4];

}; // 16 bytes

struct ether
{
    char destMac[6];
    char sourceMac[6];
    char etType[2];

}; // 14 bytes


struct iPVershion
{
    char headerLength;
    char difServiceField ;
    char totalLength [2];
    char identification[2];
    char flag;
    char fragOffset[2];
    char timeToLive;

    char proto;

    char headerChecksum[2];

    char sourceIP[4];
    char destIP[4];




}; // 20 bytes




struct tcpHeader
{
    char sourcePort[2];
    char destinationPort[2];
    char relativeSequence[4];
    char acknowledgmentNum[4];
    char headerLength;
    char flags;
    char windowSize[2];
    char checkSum[2];
    char urgentPointer[2];



};


struct udpHeader
{
    char sourcePort[2];
    char destinationPort[2];
    char headerLength[2];
    char checkSum[2];
    char urgentPointer[2];

};



int main()
{
    char temp;
    globalHeader gH;
    packetHeader pH;
    iPVershion   iPV;
    tcpHeader    tH;
    ether eT;

    FILE *iFile,*oFile;
    iFile=fopen("bal.pcap","rb");
    oFile=fopen("sal.pcap","wb");
    fread(&gH,sizeof( globalHeader),1,iFile);
    fwrite(&gH,sizeof(globalHeader),1,oFile);

   while(!feof(iFile))
   {

        fread(&pH,sizeof( packetHeader),1,iFile);
        fwrite(&pH,sizeof(packetHeader),1,oFile);
        int x=pH.packetSize[3];
        x=x << 8;
        x=x|pH.packetSize[2];
        x=x<<8;
        x=x|pH.packetSize[1];
        x=x<<8;
        x=x|pH.packetSize[0];

        unsigned char ch[x],c;


        for(int i=0;i<x;i++)
        {
            fread(&ch[i],1,1,iFile);
            fputc(ch[i],oFile);

        }



   }
    return 0;
}






