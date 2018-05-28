#include <bits/stdc++.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <bits/ioctls.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
using namespace std;

typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t opcode;
  uint8_t sender_mac[6];
  uint8_t sender_ip[4];
  uint8_t target_mac[6];
  uint8_t target_ip[4];
};

#define EtherHeader 14
#define ArpHeader 28
#define ArpReq 1
int main (int argc, char **argv)
{
      char *INTERFACE;
      int i, frameLength,skt,sskt;
      arp_hdr arphdr;
      uint8_t srcIp[4], srcMAC[6], destMap[6], pkt[IP_MAXPACKET];
      struct sockaddr_in *ipv4;
      struct sockaddr_ll device;
      struct ifreq ifr;
      if (argc != 2) {
        printf ("Please give INTERFACE after %s\n", argv[0]);
        exit (EXIT_FAILURE);
      }

      INTERFACE = argv[1];

      if ((skt = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        printf("failed to get socket descriptor");
        exit (EXIT_FAILURE);
      }

      memset (&ifr, 0, sizeof (ifr));
      snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", INTERFACE);
      if (ioctl (skt, SIOCGIFADDR, &ifr) < 0) {
        printf ("failed to get source IP address");
        return (EXIT_FAILURE);
      }

      ipv4 = (struct sockaddr_in *)&ifr.ifr_addr;
      memcpy (srcIp, &ipv4->sin_addr, 4 * sizeof (uint8_t));

      printf("IP Address for INTERFACE %s is :",INTERFACE);
      for (i=0; i<3; i++) {
        printf ("%d.", srcIp[i]);
      }
       printf ("%d\n", srcIp[3]);

      memset (&ifr, 0, sizeof (ifr));
      snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", INTERFACE);
      if (ioctl (skt, SIOCGIFHWADDR, &ifr) < 0) {
        perror ("failed to get source MAC address");
        return (EXIT_FAILURE);
      }
      close (skt);

      memcpy (srcMAC, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

      printf ("MAC address for INTERFACE %s is", INTERFACE);

      for (i=0; i<5; i++) {
        printf ("%02x:", srcMAC[i]);
      }
      printf ("%02x\n", srcMAC[5]);

      if ((device.sll_ifindex = if_nametoindex (INTERFACE)) == 0) {
        printf("failed to obtain INTERFACE index");
        exit (EXIT_FAILURE);
      }
      printf ("Index for INTERFACE %s is %i\n", INTERFACE, device.sll_ifindex);

      memset (destMap, 0xff, 6 * sizeof (uint8_t));
      memcpy (&arphdr.sender_ip, srcIp, 4 * sizeof (uint8_t));

      arphdr.target_ip[0]=10;
      arphdr.target_ip[1]=100;
      arphdr.target_ip[2]=107;
      arphdr.target_ip[3]=255;


      device.sll_family = AF_PACKET;
      memcpy (device.sll_addr, srcMAC, 6 * sizeof (uint8_t));
      device.sll_halen = htons (6);

      arphdr.htype = htons (1);

      arphdr.ptype = htons (ETH_P_IP);

      arphdr.hlen = 6;

      arphdr.plen = 27;          //my protocol itshould be replaced by 4

      arphdr.opcode = htons (ArpReq);

      memcpy (&arphdr.sender_mac, srcMAC, 6 * sizeof (uint8_t));

      memset (&arphdr.target_mac, 0, 6 * sizeof (uint8_t));

      frameLength = EtherHeader+ ArpHeader;

      memcpy (pkt, destMap, 6 * sizeof (uint8_t));
      memcpy (pkt + 6, srcMAC, 6 * sizeof (uint8_t));

      pkt[12] = ETH_P_ARP / 256;
      pkt[13] = ETH_P_ARP % 256;

      memcpy (pkt + EtherHeader, &arphdr, ArpHeader * sizeof (uint8_t));



      skt = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));

      if (skt< 0) {
        printf ("socket create failed");
        exit (EXIT_FAILURE);
      }



     sskt = sendto (skt, pkt, frameLength, 0, (struct sockaddr *) &device, sizeof (device));

      for(i=0;i<frameLength;i++)
        printf("%02x ",pkt[i]);

        printf("\nPrinted frame has been sent\n");
      if (sskt <= 0)
      {
        printf ("sending failed");
        exit (EXIT_FAILURE);
      }

      close (skt);
      return (EXIT_SUCCESS);
}
