#include<bits/stdc++.h>
#include<stdio.h>
#include <fstream>
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
    char packetSize[4];
    char packetLength[4];

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





char *arr;
int main()
{
    FILE *iFile;
    iFile=fopen("n.pcap","rb");
    globalHeader gH;
    packetHeader pH;
    fread(&gH,sizeof( globalHeader),1,iFile);
    fread(&pH,sizeof( packetHeader),1,iFile);






}





