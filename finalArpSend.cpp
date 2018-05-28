#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <bits/ioctls.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <errno.h>
#include <bits/stdc++.h>
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

#define ETH_HDRLEN 14
#define IP4_HDRLEN 20
#define ARP_HDRLEN 28
#define ARPOP_REQUEST 1
int main (int argc, char **argv)
{
  char *interface;
  int i, frameLength,skt, bytes;
  arp_hdr arphdr;
  uint8_t srcIp[4], srcMAC[6], destMap[6], pkt[IP_MAXPACKET];
  struct sockaddr_in *ipv4;
  struct sockaddr_ll device;
  struct ifreq ifr;
  if (argc != 2) {
    printf ("Usage: %s INTERFACE\n", argv[0]);
    exit (EXIT_FAILURE);
  }

  interface = argv[1];

  if ((skt = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    printf("socket() failed to get socket descriptor for using ioctl()");
    exit (EXIT_FAILURE);
  }

  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if (ioctl (skt, SIOCGIFADDR, &ifr) < 0) {
    perror ("ioctl() failed to get source IP address");
    return (EXIT_FAILURE);
  }

  ipv4 = (struct sockaddr_in *)&ifr.ifr_addr;
  memcpy (srcIp, &ipv4->sin_addr, 4 * sizeof (uint8_t));


  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if (ioctl (skt, SIOCGIFHWADDR, &ifr) < 0) {
    perror ("ioctl() failed to get source MAC address");
    return (EXIT_FAILURE);
  }
  close (skt);

  memcpy (srcMAC, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

  printf ("MAC address for interface %s is", interface);
  for (i=0; i<5; i++) {
    printf ("%02x:", srcMAC[i]);
  }
  printf ("%02x\n", srcMAC[5]);

  if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
    printf("if_nametoindex() failed to obtain interface index");
    exit (EXIT_FAILURE);
  }
  printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);

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

  arphdr.plen = 27;

  arphdr.opcode = htons (ARPOP_REQUEST);

  memcpy (&arphdr.sender_mac, srcMAC, 6 * sizeof (uint8_t));

  memset (&arphdr.target_mac, 0, 6 * sizeof (uint8_t));

  frameLength = 6 + 6 + 2 + ARP_HDRLEN;

  memcpy (pkt, destMap, 6 * sizeof (uint8_t));
  memcpy (pkt + 6, srcMAC, 6 * sizeof (uint8_t));

  pkt[12] = ETH_P_ARP / 256;
  pkt[13] = ETH_P_ARP % 256;

  memcpy (pkt + ETH_HDRLEN, &arphdr, ARP_HDRLEN * sizeof (uint8_t));



 skt = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));

  if (skt< 0) {
    printf ("socket() failed");
    exit (EXIT_FAILURE);
  }



  bytes = sendto (skt, pkt, frameLength, 0, (struct sockaddr *) &device, sizeof (device));

  for(int i=0;i<frameLength;i++)
  	printf("%02x ",pkt[i]);

  if (bytes <= 0)
  {
    printf ("sendto() failed");
    exit (EXIT_FAILURE);
  }
  else
  	printf("\n %d",bytes);



  close (skt);
  return (EXIT_SUCCESS);
}
