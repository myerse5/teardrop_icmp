/*  Copyright (C) 2011  P.D. Buchan (pdbuchan@yahoo.com)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    Original source: https://pastebin.com/62JmMddE

    Modified by Evan Myers.

*/

// Send an IPv4 ICMP packet via raw socket.
// Stack fills out layer 2 (data link) information (MAC addresses) for us.
// Values set for echo request packet, includes some ICMP data.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close(), getopt()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket()
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_RAW, IPPROTO_IP, IPPROTO_ICMP
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/ip_icmp.h>  // struct icmp, ICMP_ECHO
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq

#include <errno.h>            // errno, perror()

// Define some constants.
#define IP4_HDRLEN 20         // IPv4 header length
#define ICMP_HDRLEN 8         // ICMP header length for echo request, excludes data
#define MAX_DATALEN (IP_MAXPACKET - IP4_HDRLEN - ICMP_HDRLEN)

// Function prototypes
unsigned short int checksum (unsigned short int *, int);

int main (int argc, char **argv)
{
  int status, datalen, sd, ip_flags[4], opt;
  char interface[40];
  char src_ip[16], dst_ip[100], target[16];
  struct ip iphdr;
  struct icmp icmphdr;
  unsigned char data[MAX_DATALEN], packet[IP_MAXPACKET];
  struct addrinfo hints, *res;
  struct sockaddr_in *ipv4, sin;
  struct ifreq ifr;

  // Handle command line options, see GETOPT(3).
  char optstring[] = "i:s:d:";

  while ((opt = getopt (argc, argv, optstring)) != -1) {
    switch (opt) {
      case 'i':
        memset (&interface, 0, sizeof(interface));
        strncpy (interface, optarg, sizeof(interface) - 1);
        break;
      case 's':
        memset (&src_ip, 0, sizeof(src_ip));
        strncpy (src_ip, optarg, sizeof(src_ip) - 1);
        break;
      case 'd':
        memset (&dst_ip, 0, sizeof(target));
        strncpy (target, optarg, sizeof(target) - 1);
        break;
      default:
        exit (EXIT_FAILURE);
    }
  }


  // Submit request for a socket descriptor to lookup interface.
  if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
    perror ("socket() failed to get socket descriptor for using ioctl() ");
    exit (EXIT_FAILURE);
  }

  // Use ioctl() to lookup interface.
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if (ioctl (sd, SIOCGIFINDEX, &ifr) < 0) {
    perror ("ioctl() failed to find interface ");
    return (EXIT_FAILURE);
  }
  close (sd);
  printf ("Index for interface %s is %i\n", interface, ifr.ifr_ifindex);

  // Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  // Resolve target using getaddrinfo().
  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }
  ipv4 = (struct sockaddr_in *) res->ai_addr;
  inet_ntop (AF_INET, &(ipv4->sin_addr), dst_ip, 40);
  freeaddrinfo (res);

  // ICMP data
  datalen = 4;
  data[0] = 'T';
  data[1] = 'e';
  data[2] = 's';
  data[3] = 't';

  // IPv4 header
  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
  iphdr.ip_hl = IP4_HDRLEN / 4;

  // Internet Protocol version (4 bits): IPv4
  iphdr.ip_v = 4;

  // Type of service (8 bits)
  iphdr.ip_tos = 0;

  // Total length of datagram (16 bits): IP header + ICMP header + ICMP data
  iphdr.ip_len = htons (IP4_HDRLEN + ICMP_HDRLEN + datalen);

  // ID sequence number (16 bits): unused, since single datagram
  iphdr.ip_id = htons (0);

  // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram
  // Zero (1 bit)
  ip_flags[0] = 0;

  // Do not fragment flag (1 bit)
  ip_flags[1] = 0;

  // More fragments following flag (1 bit)
  ip_flags[2] = 0;

  // Fragmentation offset (13 bits)
  ip_flags[3] = 0;

  iphdr.ip_off = htons ((ip_flags[0] << 15)
                      + (ip_flags[1] << 14)
                      + (ip_flags[2] << 13)
                      +  ip_flags[3]);

  // Time-to-Live (8 bits): default to maximum value
  iphdr.ip_ttl = 255;

  // Transport layer protocol (8 bits): 1 for ICMP
  iphdr.ip_p = IPPROTO_ICMP;

  // Source IPv4 address (32 bits)
  inet_pton (AF_INET, src_ip, &(iphdr.ip_src));

  // Destination IPv4 address (32 bits)
  inet_pton (AF_INET, dst_ip, &iphdr.ip_dst);

  // IPv4 header checksum (16 bits): set to 0 when calculating checksum
  iphdr.ip_sum = 0;
  iphdr.ip_sum = checksum ((unsigned short int *) &iphdr, IP4_HDRLEN);

  // ICMP header
  // Message Type (8 bits): echo request
  icmphdr.icmp_type = ICMP_ECHO;

  // Message Code (8 bits): echo request
  icmphdr.icmp_code = 0;

  // Identifier (16 bits): usually pid of sending process - pick a number
  icmphdr.icmp_id = htons (1000);

  // Sequence Number (16 bits): starts at 0
  icmphdr.icmp_seq = htons (0);

  // ICMP header checksum (16 bits): set to 0 when calculating checksum
  icmphdr.icmp_cksum = 0;
  char tmp[ICMP_HDRLEN + datalen];
  memcpy (tmp, &icmphdr, ICMP_HDRLEN);
  memcpy (tmp + ICMP_HDRLEN, data, datalen);
  icmphdr.icmp_cksum = checksum ((unsigned short int *) tmp, ICMP_HDRLEN + datalen);


  // Prepare packet.
  memset (&packet, 0, sizeof (packet));
  memcpy (packet, &iphdr, IP4_HDRLEN);
  memcpy (packet + IP4_HDRLEN, &icmphdr, ICMP_HDRLEN);
  memcpy (packet  + IP4_HDRLEN + ICMP_HDRLEN, data, datalen);

  // The kernel is going to prepare layer 2 information (ethernet frame header)
  // for us. For that, we need to specify a destination for the kernel in order
  // for it to decide where to send the raw datagram. We fill in a struct
  // in_addr with the desired destination IP address, and pass this structure
  // to the sendto() function.
  memset (&sin, 0, sizeof (struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = iphdr.ip_dst.s_addr;

  // Submit request for a raw socket descriptor.
  if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
    perror ("socket() failed ");
    exit (EXIT_FAILURE);
  }


  int on = 1, off = 0;
  // Enable writing the IP header information.
  if (setsockopt (sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
    perror ("setsockopt() failed to write IP header ");
    exit (EXIT_FAILURE);
  }

  // Bind socket to interface index.
  if (setsockopt (sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (ifr)) < 0) {
    perror ("setsockopt() failed to bind to interface ");
    exit (EXIT_FAILURE);
  }

  bind (sd, (struct sockaddr*)&sin, sizeof(sin));
  // Send packet.
  if (sendto (sd, packet, IP4_HDRLEN + ICMP_HDRLEN + datalen, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)  {
    perror ("sendto() failed ");
    exit (EXIT_FAILURE);
  } else {
    printf ("Success?\n");
  }

  struct sockaddr_in rec;
  unsigned char pkt[IP_MAXPACKET];
  memset (&pkt, 0, sizeof(pkt));

  if (recvfrom (sd, (void*)pkt, sizeof(struct ip) + sizeof(struct icmp) + datalen, 0, NULL, (socklen_t*)sizeof (struct sockaddr)) < 0)  {
    perror ("recvfrom() failed ");
    exit (EXIT_FAILURE);
  }

  struct ip *ip = (struct ip *)pkt;
  struct icmp *icmp = (struct icmp *)(pkt + sizeof(struct ip));

  printf("%s %s %d\n",(char*)inet_ntoa(*(struct in_addr*)&ip->ip_dst),
                                          (char*)inet_ntoa(*(struct in_addr*)&ip->ip_src),
                                          icmp->icmp_type);

  close (sd);
  return (EXIT_SUCCESS);
}

// Checksum function
unsigned short int checksum (unsigned short int *addr, int len)
{
  int nleft = len;
  int sum = 0;
  unsigned short int *w = addr;
  unsigned short int answer = 0;

  while (nleft > 1) {
    sum += *w++;
    nleft -= sizeof (unsigned short int);
  }

  if (nleft == 1) {
    *(unsigned char *) (&answer) = *(unsigned char *) w;
    sum += answer;
  }

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}
