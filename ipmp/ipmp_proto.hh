/*
 * IP Measurement Protocol (IPMP)
 *
 * Adaptation to Click Modular Router by Florian Sesser 2010
 * http://www.so.in.tum.de/
 *
 * Original implementation By Matthew Luckie 2000, 2001, 2002
 * http://moat.nlanr.net/AMP/AMP/IPMP/
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety,
 * (2) distributions including binary code include the above copyright
 * notice and this paragraph in its entirety in the documentation or other
 * materials provided with the distribution, and (3) derivative work or other
 * resulting materials based on this software product display the following
 * acknowledgement: ``This work utilizes software developed in whole or in
 * part by the National Laboratory for Applied Network Research (NLANR) at
 * the University of California San Diego's San Diego Supercomputer Center,
 * under a National Science Foundation Cooperative Agreement No. ANI-9807479,
 * and its contributors.''
 * 
 * Neither the NLANR name, the name of the University, funding organizations,
 * nor the names of its contributors may be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef _NETINET_IPMP_H
#define _NETINET_IPMP_H

#define IPPROTO_IPMP 169

#define IPMP_ECHO    0x80
#define IPMP_PROBE   0x04
#define IPMP_INFO    0x02
#define IPMP_REQUEST 0x01

/* In linux kernelspace, these are already defined. */
#ifndef u8
typedef unsigned char u8;
#endif
#ifndef u16
typedef unsigned short u16;
#endif
#ifndef u32
typedef unsigned int u32;
#endif
#ifndef u64
typedef unsigned long long u64;
#endif

struct ipmp {
	u8	version;
	u8	options;
	u8	faux_proto;
	u8	reserved;

	u16	id;
	u16	seq;

	u16	faux_srcport;
	u16	faux_dstport;
};

struct ipmp_trailer {
	u16	path_pointer;
	u16	checksum;
};

/*
 * IPMP Time format
 * this is like timespec except it ensures 32bits are used for sec and
 * nsec on 64 bit platforms such as the alpha
 */
struct ipmptime {
	u32	sec;
	u32	nsec;
};

/*
 * The IPMP path record
 * This is carried inside the ipmp_echo packet
 */
struct ipmp_pathrecord {
	u8	ttl;
	u8	flowc;
	u16	sec;
	u32	nsec;
	struct in_addr ip;
};
struct ipmp_pathrecord6 {
	u8	hlim;
	u8	flowc;
	u16	sec;
	u32	nsec;
	struct in6_addr ip;
};

/*
 * The IPMP real time reference point structure
 * This structure is carried in an ipmp_reply packet
 */
struct ipmp_rtrp {
	struct ipmptime real_time;
	struct ipmptime reported_time;
};

/*
 * The IPMP inforeply packet format
 */
struct ipmp_inforeply {
	u16		length;
	u16		pdp; /* performance data pointer */
	struct in_addr  forwarding_ip;
	struct ipmptime accuracy;
	struct ipmptime overhead;
};


typedef struct ipmp_ping_args {
	u8		ip_v;		/* version of IP to encapsulate    */
	u8		ttl;		/* ttl of the echo request         */
	u16		len;		/* size of the ipmp packet to send */
	struct ipmptime timestamp;	/* time the packet was sent        */
	u16		id;		/* the id of the packet            */
	u16		seq;		/* the sequence number             */
	u8		tos;		/* the traffic class               */
	struct sockaddr* dst;		/* the destination address         */
	struct sockaddr* src;		/* the source address to spoof     */
} ipmp_ping_args_t;

/*
 * from linux/include/net/protocol.h (as of 2.6.26),
 * only used for some hash function or so
 */
#define MAX_INET_PROTOS 256


/*
 * Stuff for M Luckie's HashMap
 */
struct ipmp_flow_key {
	u32 src;
	u32 dst;
	u16 id;
};

struct ipmp_flow {
	struct ipmp_flow *next;
	struct ipmp_flow *prev;
	Timer*		timer;
	unsigned int	key;
	u32		src;
	u32		dst;
	u16		id;
	u8		flowc;
};

struct ipmp_flow_head {
	unsigned int		length;
	struct ipmp_flow*	head;
	struct ipmp_flow*	tail;
};

struct ipmp_flowcache {
	struct ipmp_flow_head *hashbase;
	// rwlock_t	hashlock;
	unsigned int	hashsecret;
	unsigned int	hashsize;
	unsigned int	hashmask;
	unsigned int	bucket_limit;
	unsigned int	cache_count;
	unsigned int	cache_limit;
	Timestamp	lifetime;
};
/* End of stuff for M Luckie's HashMap */


#endif /* _NETINET_IPMP_H */
