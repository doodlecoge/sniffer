
#ifndef CONSTANTS_H
#define CONSTANTS_H

/* constants definition here */

#ifndef BUF_SZ
#define BUF_SZ 2048
#endif
#define EIGHT_ZERO

/*					
	0000000000000000	0000000000	0000	00
*/

#define PROTO_802_3			1
#define PROTO_ETHERNET_2	2

#define PROTO_ARP			3
#define PROTO_IP			4
#define PROTO_IP6			5

#define PROTO_ICMP			6
#define PROTO_TCP			7
#define PROTO_UDP			8

#define PROTO_HTTP			9
#define PROTO_FTP			10

#endif /* end of constants.h */


#define DBG_ON

#define FILE_INCREMENT 128
#define MAX_THREADS 32










/* ARP protocol opcodes. */
#define	ARPOP_REQUEST_CC		1		/* ARP request.  */
#define	ARPOP_REPLY_CC			2		/* ARP reply.  */
#define	ARPOP_RREQUEST_CC		3		/* RARP request.  */
#define	ARPOP_RREPLY_CC			4		/* RARP reply.  */
#define	ARPOP_InREQUEST_CC		8		/* InARP request.  */
#define	ARPOP_InREPLY_CC		9		/* InARP reply.  */
#define	ARPOP_NAK_CC			10		/* (ATM)ARP NAK.  */


/* icmp type */
#define ICMP_ECHOREPLY_CC		0	/* Echo Reply			*/
#define ICMP_DEST_UNREACH_CC	3	/* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH_CC	4	/* Source Quench		*/
#define ICMP_REDIRECT_CC		5	/* Redirect (change route)	*/
#define ICMP_ECHO_CC			8	/* Echo Request			*/
#define ICMP_TIME_EXCEEDED_CC	11	/* Time Exceeded		*/
#define ICMP_PARAMETERPROB_CC	12	/* Parameter Problem		*/
#define ICMP_TIMESTAMP_CC		13	/* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY_CC	14	/* Timestamp Reply		*/
#define ICMP_INFO_REQUEST_CC	15	/* Information Request		*/
#define ICMP_INFO_REPLY_CC		16	/* Information Reply		*/
#define ICMP_ADDRESS_CC			17	/* Address Mask Request		*/
#define ICMP_ADDRESSREPLY_CC	18	/* Address Mask Reply		*/
#define NR_ICMP_TYPES_CC		18


/* tcp flag mask */
#  define TH_FIN_CC		0x01
#  define TH_SYN_CC		0x02
#  define TH_RST_CC		0x04
#  define TH_PUSH_CC	0x08
#  define TH_ACK_CC		0x10
#  define TH_URG_CC		0x20






