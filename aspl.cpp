#include <bits/stdc++.h>
#include <stdio.h>
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



struct arpHeader
{


    unsigned char hardwareType[2];
    unsigned char protocol[2];
    unsigned char hardwareSize;
    unsigned char protocolSize;
    unsigned char opcodeRequest[2];
    unsigned char senderMac[6];
    unsigned char senderIP[4];
    unsigned char targetMac[6];
    unsigned char targetIP[4];


};


int total=0;

int ipv4=0;
int ipv6=0;
int arp=0;
int ot=0;


string checkLinLayer(int et_1,int et_2)
{
      if(et_1==(int)8 && et_2==(int)0)
    {
        ipv4++;
        return "IPV4";
    }
    else if(et_1==(int)8 && et_2==(int)6)
    {
       arp++;
        return "ARP";

    }
    else if(et_1==(int)134 && et_2==(int)221)
    {
        ipv6++;
        return "IPV6";
    }
    else
    {
        ot++;
        return "Others";

    }


}
int tcp=0;
int udp=0;
int icmp=0;
int igmp=0;
int ott=0;


string checkTransLayer(int proto)
{
    if(proto==6)
    {
        tcp++;
        return "TCP";
    }
    else if(proto==17)
    {

        udp++;
        return "UDP";


    }
    else if(proto==1)
    {
        icmp++;
        return "ICMP";
    }
    else if(proto==2)
    {

        igmp++;
        return "IGMP";
    }
    else
    {
        ott++;
        return "Other";
    }

}

  void printPcap(packetHeader pH,FILE* file,unsigned char ch[],int x)
  {
    fwrite(&pH,sizeof(packetHeader),1,file);



            for(int i=0;i<x;i++)
            {


                if (i == 0 ) {
                    printf("%06X  ", i);
                  }
                  else {
                    if (i%16 == 0)
                      printf("\n%06X  ", i);
                    else if (i%16 == 8)
                      printf(" -- ");
                    else
                      printf(" ");
                  }

                  printf("%02X", ch[i]);


                fputc(ch[i],file);

            }




  }





void printFileByTransProtocol(FILE *iFile,FILE *otFile,FILE *tcpFile,FILE *udpFile,FILE *icmpFile,FILE *igmpFile)
{

    total=0;
    globalHeader gH;
    packetHeader pH;


    iFile=fopen("a.pcap","rb");
    tcpFile=fopen("tcp.pcap","wb");
    udpFile=fopen("udp.pcap","wb");
    icmpFile=fopen("icmp.pcap","wb");
    igmpFile=fopen("igmp.pcap","wb");
    otFile=fopen("other_t.pcap","wb");

    fread(&gH,sizeof( globalHeader),1,iFile);
    fwrite(&gH,sizeof(globalHeader),1,otFile);
    fwrite(&gH,sizeof(globalHeader),1,icmpFile);
    fwrite(&gH,sizeof(globalHeader),1,igmpFile);
    fwrite(&gH,sizeof(globalHeader),1,tcpFile);
    fwrite(&gH,sizeof(globalHeader),1,udpFile);

   while(!feof(iFile))
   {

        fread(&pH,sizeof( packetHeader),1,iFile);
        int x=pH.packetSize[3];
        x=x << 8;
        x=x|pH.packetSize[2];
        x=x<<8;
        x=x|pH.packetSize[1];
        x=x<<8;
        x=x|pH.packetSize[0];

        unsigned char ch[x],c;


        for(int i=0;i<x;i++)
            fread(&ch[i],1,1,iFile);

        int proto;
        proto=(int)ch[23];

        string s=checkTransLayer(proto);

        total++;

        if(s=="TCP")
        {
            cout<<endl;
            cout<<endl;
            cout<<endl;
            cout<<total<<endl;
            cout<<endl;
            cout<<"Transport protocol "<< s <<" NO:"<<tcp<<endl;
            cout<<endl;


           // fwrite(&pH,sizeof(packetHeader),1,tcpFile);

            printPcap(pH,tcpFile,ch,x);

    }

    else if(s=="UDP")
   {
            cout<<endl;
            cout<<endl;
            cout<<total<<endl;
            cout<<endl;
            cout<<"Transport protocol "<< s <<" NO:"<<udp<<endl;
            cout<<endl;



            printPcap(pH,udpFile,ch,x);


        }

        else if(s=="ICMP")
        {
            cout<<endl;
            cout<<endl;
            cout<<total<<endl;
            cout<<endl;
            cout<<"Transport protocol "<< s <<" NO:"<<icmp<<endl;
            cout<<endl;
            printPcap(pH,icmpFile,ch,x);

        }




     else if(s=="IGMP")
        {
            cout<<endl;
            cout<<endl;
            cout<<total<<endl;printPcap(pH,udpFile,ch,x);
            cout<<endl;
            cout<<"Transport protocol "<< s <<" NO:"<<igmp<<endl;
            cout<<endl;

            printPcap(pH,igmpFile,ch,x);
           }


     else if(s=="Other")
           {
                    cout<<endl;
                    cout<<endl;
                    cout<<total<<endl;
                    cout<<endl;
                    cout<<"Transport protocol "<< s <<" NO:"<<ott<<endl;
                    cout<<endl;
                    printPcap(pH,otFile,ch,x);

            }
   }

   }


void printFileByEtlayer(FILE *iFile,FILE *oFile,FILE *arpFile,FILE *ip4File,FILE *ip6File)
{

    total=0;

    globalHeader gH;
    packetHeader pH;

    iFile=fopen("a.pcap","rb");
    arpFile=fopen("arp.pcap","wb");
    ip4File=fopen("ip4.pcap","wb");
    ip6File=fopen("ip6.pcap","wb");
    oFile=fopen("other.pcap","wb");

    fread(&gH,sizeof( globalHeader),1,iFile);
    fwrite(&gH,sizeof(globalHeader),1,oFile);
    fwrite(&gH,sizeof(globalHeader),1,ip4File);
    fwrite(&gH,sizeof(globalHeader),1,ip6File);
    fwrite(&gH,sizeof(globalHeader),1,arpFile);

   while(!feof(iFile))
   {

        fread(&pH,sizeof( packetHeader),1,iFile);
        int x=pH.packetSize[3];
        x=x << 8;
        x=x|pH.packetSize[2];
        x=x<<8;
        x=x|pH.packetSize[1];
        x=x<<8;
        x=x|pH.packetSize[0];

        unsigned char ch[x],c;




        for(int i=0;i<x;i++)
            fread(&ch[i],1,1,iFile);



        int etx,ety,proto;
        etx=(int)ch[12];
        ety=(int)ch[13];


        string s=checkLinLayer(etx,ety);
        total++;
        if(s=="IPV4")
        {
            cout<<endl;
            cout<<endl;
            cout<<total<<endl;
            cout<<endl;
            cout<<"IPV4 No: "<<ipv4<<endl;
            cout<<endl;
            printPcap(pH,ip4File,ch,x);
        }


   else if(s=="IPV6")
   {
            cout<<endl;
            cout<<endl;
            cout<<total<<endl;
            cout<<endl;
            cout<<"IPV6 No: "<<ipv6<<endl;
            cout<<endl;

        printPcap(pH,ip6File,ch,x);
   }

   else if(s=="ARP")
   {
        cout<<endl;
        cout<<endl;
        cout<<total<<endl;
        cout<<endl;
        cout<<"ARP No: "<<arp<<endl;
        cout<<endl;

        printPcap(pH,arpFile,ch,x);
    }

    else
    {
        cout<<endl;
        cout<<endl;
        cout<<total<<endl;

        cout<<endl;
        cout<< "Other type No:"<<ot<<endl;
        cout<<endl;

       printPcap(pH,oFile,ch,x);


   }
   }



}




int main()
{
    FILE *iFile,*oFile,*arpFile,*ip4File,*ip6File,*tcpFile,*udpFile,*icmpFile,*igmpFile,*otFile;

    printFileByEtlayer(iFile,oFile,arpFile,ip4File,ip6File);
    cout<<endl;
    cout<<endl;
    printFileByTransProtocol(iFile,otFile,tcpFile,udpFile,icmpFile,igmpFile);

    return 0;
}

