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

// Function prototypes
unsigned short int checksum (unsigned short int *, int);

int main (int argc, char **argv)
{
  int status, datalen, sd, *ip_flags, opt;
  const int on = 1;
  char *interface, *target, *src_ip, *dst_ip;
  struct ip iphdr;
  struct icmp icmphdr;
  unsigned char *data, *packet;
  struct addrinfo hints, *res;
  struct sockaddr_in *ipv4, sin;
  struct ifreq ifr;
  void *tmp;


  // Valid command line options string, see GETOPT(3).
  char optstring[] = "i:s:d:";

  // Allocate memory for various arrays.
  // Maximum ICMP payload size = 65535 - IPv4 header (20 bytes) - ICMP header (8 bytes)
  tmp = (unsigned char *) malloc ((IP_MAXPACKET - IP4_HDRLEN - ICMP_HDRLEN) * sizeof (unsigned char));
  if (tmp != NULL) {
    data = tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'data'.\n");
    exit (EXIT_FAILURE);
  }
  memset (data, 0, (IP_MAXPACKET - IP4_HDRLEN - ICMP_HDRLEN) * sizeof (unsigned char));

  tmp = (unsigned char *) malloc (IP_MAXPACKET * sizeof (unsigned char));
  if (tmp != NULL) {
    packet = tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'packet'.\n");
    exit (EXIT_FAILURE);
  }
  memset (packet, 0, IP_MAXPACKET * sizeof (unsigned char));

  tmp = (char *) malloc (40 * sizeof (char));
  if (tmp != NULL) {
    interface = tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'interface'.\n");
    exit (EXIT_FAILURE);
  }
  memset (interface, 0, 40 * sizeof (char));

  tmp = (char *) malloc (40 * sizeof (char));
  if (tmp != NULL) {
    target = tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'target'.\n");
    exit (EXIT_FAILURE);
  }
  memset (target, 0, 40 * sizeof (char));

  tmp = (char *) malloc (16 * sizeof (char));
  if (tmp != NULL) {
    src_ip = tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'src_ip'.\n");
    exit (EXIT_FAILURE);
  }
  memset (src_ip, 0, 16 * sizeof (char));

  tmp = (char *) malloc (16 * sizeof (char));
  if (tmp != NULL) {
    dst_ip = tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'dst_ip'.\n");
    exit (EXIT_FAILURE);
  }
  memset (dst_ip, 0, 16 * sizeof (char));

  tmp = (int *) malloc (4 * sizeof (int));
  if (tmp != NULL) {
    ip_flags = tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'ip_flags'.\n");
    exit (EXIT_FAILURE);
  }
  memset (ip_flags, 0, 4 * sizeof (int));


  // Collect interface and IP values from command line options.
  while ((opt = getopt (argc, argv, optstring)) != -1) {
    switch (opt) {
      case 'i':
        interface = optarg;
        break;
      case 's':
        strcpy (src_ip, optarg);
        break;
      case 'd':
        strcpy (target, optarg);
        break;
      default:
        fprintf (stderr, "Invalid argument \"%d\"", opt);
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
  tmp = &(ipv4->sin_addr);
  inet_ntop (AF_INET, tmp, dst_ip, 40);
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
  iphdr.ip_ttl = 16;

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

  // Prepare packet.



  // Next part of packet is upper layer protocol header.
  memcpy ((packet ), &icmphdr, ICMP_HDRLEN);

  // Finally, add the ICMP data.
  memcpy (packet  + ICMP_HDRLEN, data, datalen);

  // Calculate ICMP header checksum
  icmphdr.icmp_cksum = checksum ((unsigned short int *) (packet ), ICMP_HDRLEN + datalen);
  memcpy ((packet ), &icmphdr, ICMP_HDRLEN);


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


  // Bind socket to interface index
  if (setsockopt (sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (ifr)) < 0) {
    perror ("setsockopt() failed to bind to interface ");
    exit (EXIT_FAILURE);
  }

  bind (sd, (struct sockaddr*)&sin, sizeof(sin));
  // Send packet.
  if (sendto (sd, packet, ICMP_HDRLEN + datalen, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0)  {
    perror ("sendto() failed ");
    exit (EXIT_FAILURE);
  }

  struct sockaddr_in rec;
  unsigned char * pkt = (unsigned char *) malloc (2048);

  if (recvfrom (sd, (void*)pkt, sizeof(struct ip) + sizeof(struct icmp) + datalen, 0, NULL, (socklen_t*)sizeof (struct sockaddr)) < 0)  {
    perror ("recvfrom() failed ");
    exit (EXIT_FAILURE);
  }

  struct ip *ip = (struct ip *)pkt;
  struct icmp *icmp = (struct icmp *)(pkt + sizeof(struct ip));

  printf("%s %s %d\n",(char*)inet_ntoa(*(struct in_addr*)&ip->ip_dst),
                                          (char*)inet_ntoa(*(struct in_addr*)&ip->ip_src),
                                          icmp->icmp_type);

  free (pkt);
  close (sd);

  // Free allocated memory.
  free (data);
  free (packet);
  free (interface);
  free (target);
  free (src_ip);
  free (dst_ip);
  free (ip_flags);

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
