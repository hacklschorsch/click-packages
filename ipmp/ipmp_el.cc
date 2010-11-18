/*
 * ipmp.{cc,hh} -- IPMP element
 *
 * Florian Sesser, using work by Matthew Luckie and Anthony McGregor.
 *                 (and of course Eddie Kohler, see below).
 *
 * Copyright (c) 2010 Self-Organizing Systems, Technical University of Munich
 *
 */

/*
 * Copyright (c) 2000 Massachusetts Institute of Technology
 * Copyright (c) 2000 Mazu Networks, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

/* ALWAYS INCLUDE <click/config.h> FIRST */
#include <click/config.h>
#include <click/confparse.hh>

#include <clicknet/ip.h>

#include <click/timer.hh>
#include <click/timestamp.hh>

#include <click/packet.hh>
#include <click/packet_anno.hh>

#include <clicknet/ip.h>
#include <clicknet/ether.h>

#include <click/error.hh>

#include "ipmp_el.hh"

CLICK_DECLS

// We do not decrease TTLs ourselves anymore, but it still has to be done.
// Use the DecIPTTL element (see the examples in the conf-examples/ directory.
//
// extern "C" {
// static inline int ip_decrease_ttl(struct click_ip *iph)
// {
// 	u32 check = (u32)iph->ip_sum;
// 	check += (u32)htons(0x0100);
// 	iph->ip_sum = (u16)(check + (check>=0xFFFF));
// 	return --iph->ip_ttl;
// }
// }

IPMP::IPMP() : ifc(this)
{
}


IPMP::~IPMP()
{
}


int IPMP::initialize(ErrorHandler *errh)
{
	return 0 == errh;
}


int IPMP::configure(Vector<String>& conf, ErrorHandler* errh)
{
	/* defaults: */
	sysctl_ipheader_cksum = true;
	sysctl_payload_cksum = true;
	sysctl_debug = false;
	sysctl_flowc = true;

	/* Parameter parsing */
	if (cp_va_kparse(conf, this, errh,

		/* mandatory: */
		"ADDR", cpkP+cpkM, cpIPAddress, &IPv4Address,

		/* optional */
		"IPHCHK", cpkN, cpBool, &sysctl_ipheader_cksum,
		"PAYLOADCHK", cpkN, cpBool, &sysctl_payload_cksum,
		"DEBUG", cpkN, cpBool, &sysctl_debug,
		"FLOWC", cpkN, cpBool, &sysctl_flowc,

		/* argument list always terminated by cpEnd */
		cpEnd) < 0) {
		return -1;
	}

	return 0;
}


void IPMP::push(int port, Packet* p)
{
	const struct ipmp* ipmphdr;
	WritablePacket* wp;

	// mostly to suppress compile-time warning
	if (port != 0) {
		click_chatter("Ignored packet: input port != 0.");
		p->kill();
		return;
	}

	/* Is this an unicast packet? */
	if (p->packet_type_anno() == Packet::BROADCAST
			|| p->packet_type_anno() == Packet::MULTICAST) {

		if(sysctl_debug != 0)
			click_chatter("Ignored broadcast packet.");

		goto slipthrough;
	}

	/* Is this an IP packet? */
	if (!p->has_network_header()) {

		if(sysctl_debug != 0)
			click_chatter("Ignored packet: network_header not "
					"set.");

		goto slipthrough;
	}

	/* The transport_header points to the IPMP part right after the IPh */
	if (!p->has_transport_header()) {

		if(sysctl_debug != 0)
			click_chatter("Ignored packet: transport_header not "
					"set.");

		goto slipthrough;
	}

	/* Is the packet of IPMP Echo type? */
	ipmphdr = (const struct ipmp *)(p->transport_header());
	if((ipmphdr->options & IPMP_ECHO) == 0) {

		if(sysctl_debug != 0)
			click_chatter("Ignored packet: Not of IPMP Echo type.");

		goto slipthrough;
	}

	/* Simple sanity check: Is the packet big enough? */
	if (p->transport_length() < (int)(sizeof(struct ipmp)
				+ sizeof(struct ipmp_trailer))) {

		if(sysctl_debug != 0)
			click_chatter("Ignored packet: Too small to be a "
					"valid IPMP Echo request.");

		goto slipthrough;
	}

	/* check ip header checksum */
	if (sysctl_ipheader_cksum) {
		if (click_in_cksum(p->network_header(),
					p->network_header_length()) != 0) {

			if(sysctl_debug != 0)
				click_chatter("Ignored packet: IP header "
						"checksum failed.");

			goto slipthrough;
		}
	}

	/* check payload checksum */
	if (sysctl_payload_cksum) {
		if (click_in_cksum(p->transport_header(),
					p->transport_length()) != 0) {

			if(sysctl_debug != 0)
				click_chatter("Ignored packet: IPMP Payload "
						"checksum failed.");

			goto slipthrough;
		}
	}

	/*
	 * The packet passed all checks. Now, begin the IPMP magic.
	 *
	 * We will modify the packet:
	 *
	 *   If we reply, we modify the incoming packet and push it out
	 *     instead of creating a new one.
	 *
	 *   If we forward it, we try to insert a Path Record.
	 *
	 * (don't use p after uniqueification!)
	 */
	wp = p->uniqueify();
	if (!wp) // out of memory
		return;

	if (wp->ip_header()->ip_dst.s_addr == IPv4Address.addr()) {
		/* we are the destination, handle the request/reply */
		if(ipmphdr->options & IPMP_REQUEST)
			ipmp_handle_echorequest(wp);
		else
			ipmp_handle_echoreply(wp);
	} else {
		/* the packet is not for us, insert a PR and fwd it! */
		ipmp_forward(wp);
	}

	return;

slipthrough:
	if (noutputs() == 4)
		output(3).push(p);
	else
		p->kill();
}


u16 IPMP::ipmp_pr(struct ipmp_pathrecord *pr, u32 addr, Timestamp ts, u8 ttl,
		u8 flowc)
{
	u16  *w, cksum;
	u32   sum;

	pr->sec  = htons(ts.sec() & 0xffff);
	pr->nsec = htonl(ts.nsec());

	pr->ip.s_addr = addr;
	pr->flowc     = 0x80 | (flowc & 0xf);
	pr->ttl       = ttl;

	/*
	 * calculate a new checksum for the path record that includes the
	 * update made to the path pointer field
	 */
	w     = (u16 *)pr;
	sum   = *w++; sum += *w++;
	sum  += *w++; sum += *w++;
	sum  += *w++; sum += *w;
	sum  += htons(sizeof(struct ipmp_pathrecord));

	sum   = (sum >> 16) + (sum & 0xffff); sum += (sum >> 16);
	cksum = ~sum;

	return cksum;
}


/*
 * ipmp_forward
 *
 * this function inserts a path record into an IPMP echo packet if there is
 * space.
 */
void IPMP::ipmp_forward(WritablePacket *skb)
{
	struct click_ip* iph = skb->ip_header();
	struct ipmp* ipmp = (struct ipmp *)skb->transport_header();;
	u8 flowc;

	/* get flow counter */
	flowc = ifc.flowc_get(iph->ip_src.s_addr, iph->ip_dst.s_addr, ipmp->id);

	/* insert the path record */
	ipmp_insertpathrecord(skb, IPv4Address.addr(), iph->ip_ttl, flowc);

	output(0).push(skb);
}


/*
* ipmp_insertpathrecord
*
* insert a path record into the echo packet
*
* Notes:
*
*	skb->len and iph->tot_len count from the beginning of the IP
*	 header to the end of the packet
*/
int IPMP::ipmp_insertpathrecord(WritablePacket *skb,u32 addr,u8 ttl,u8 flowc)
{
	struct click_ip*	iph;
	struct ipmp_pathrecord*	ipmp_pathrecord;
	struct ipmp_pathrecord	pr;
	struct ipmp_trailer*	ipmp_trailer;
	struct ipmp_trailer	tl;
	int	iphdrlen;
	u16	pp;
	u16	len;
	u32	sum;
	u8	ttl_pre;

	iph      = skb->ip_header();
	iphdrlen = skb->ip_header_length();
	len      = ntohs(iph->ip_len);

	ipmp_trailer = (struct ipmp_trailer *)(skb->end_data() - 4);
	memcpy(&tl, ipmp_trailer, 4);

	pp = ntohs(tl.path_pointer);
	if(len < pp + iphdrlen + sizeof(struct ipmp_pathrecord) ||
		pp < sizeof(struct ipmp)) {
		if(sysctl_debug != 0) {
		  click_chatter("ipmp_ipr: %d < %d + %d + sizeof pr || %d "
				  "< ipmp\n", len, pp, iphdrlen, pp);
		}
		return 0;
	}

	ipmp_pathrecord = (struct ipmp_pathrecord*)(skb->transport_header()
							+ pp);
	/* may we insert a path record where pp points to? */
	if((ttl_pre = ipmp_pathrecord->ttl) < ttl) {
		if(sysctl_debug != 0) {
			click_chatter("ipmp_ipr: ttl %d < ttl %d",
					ipmp_pathrecord->ttl, ttl);
		}
		return 0;
	}

	/*
	 * if available, use the packet's timestamp_anno;
	 * else, generate a timestamp now.
	 */
	Timestamp ts;
	if (skb->timestamp_anno()) {

		if (sysctl_debug)
			click_chatter("Used packet's timestamp annotation "
					"(good).");

		ts = skb->timestamp_anno();
	} else {

		if (sysctl_debug)
			click_chatter("Had to generate timestamp on the fly "
					"(packet had no timestamp_anno).");

		ts = Timestamp::now();
	}

	sum = ipmp_pr(&pr, addr, ts, ttl, flowc);

	/*
	 * copy in the new path record
	 */
	memcpy(skb->transport_header() + pp, &pr, sizeof(pr));

	/* update the path pointer and the checksum */
	tl.path_pointer = htons(pp + sizeof(pr));
	sum += (tl.checksum + htons(ttl_pre << 8));
	tl.checksum = (sum & 0xffff) + (sum >> 16);
	if(tl.checksum == 0xffff)
		tl.checksum = 0;
	memcpy(ipmp_trailer, &tl, 4);

	return 1;
}


/* handle an incoming echo reply */
void IPMP::ipmp_handle_echoreply(WritablePacket *skb)
{
	struct click_ip* iph  = skb->ip_header();
	struct ipmp* ipmp = (struct ipmp *)skb->transport_header();

	/* decrement the packet's ttl */
	// ip_decrease_ttl(iph);

	/* get flow counter */
	u8 flowc = ifc.flowc_get(iph->ip_src.s_addr, iph->ip_dst.s_addr,
					ipmp->id);

	/* insert a path record if there is space */
	ipmp_insertpathrecord(skb, iph->ip_dst.s_addr, iph->ip_ttl, flowc);

	output(1).push(skb);
}


/*
 * Reply to an IPMP echo request.
 */
void IPMP::ipmp_handle_echorequest(WritablePacket *skb)
{
	struct click_ether* ethh = skb->ether_header();
	struct click_ip* iph = skb->ip_header();
	struct ipmp* ipmp = (struct ipmp*)skb->transport_header();
	struct ipmp_trailer* ipmp_trailer =
		(struct ipmp_trailer *)(skb->end_data() - 4);

	/* get flow counter */
	u8 flowc = ifc.flowc_get(iph->ip_src.s_addr, iph->ip_dst.s_addr,
					ipmp->id);

	/* swap the source and the dest IP addresses to return the packet */
	struct in_addr tmp_addr = iph->ip_dst;
	iph->ip_dst = iph->ip_src;
	iph->ip_src = tmp_addr;

	/* also swap ethernet address, shouldn't harm our cause	 */
	if (ethh) {
		u8 eth_tmp[6];
		memcpy(&eth_tmp, ethh->ether_dhost, 6);
		memcpy(ethh->ether_dhost, ethh->ether_shost, 6);
		memcpy(ethh->ether_shost, &eth_tmp, 6);
	}

	/* decrement the packet's ttl */
	// ip_decrease_ttl(iph);

	/* turn the packet into an echo reply */
	ipmp->options &= (~IPMP_REQUEST);
	/* and change chksum appropriatly */
	u16 cksum = ipmp_trailer->checksum;
	u32 sum = cksum + htons(0x0001);
	cksum = (sum & 0xffff) + (sum >> 16);
	if(cksum == 0xffff) cksum = 0;
	ipmp_trailer->checksum = cksum;

	/* insert a path record (if there is space etc etc) */
	ipmp_insertpathrecord(skb, iph->ip_src.s_addr, iph->ip_ttl, flowc);

	/* set annotations, borrowed from icmppingresponder */
	skb->set_dst_ip_anno(iph->ip_dst);
	skb->set_timestamp_anno(Timestamp::now());
	SET_PAINT_ANNO(skb, 0);

	output(2).push(skb);
}


/*
 * Constructor for FlowCache
 */
IPMP::FlowCache::FlowCache(IPMP* parent_ipmp)
{
	this->parent = parent_ipmp;
	hashsecret = rand();
	hashsize     = 512;
	hashmask     = hashsize - 1;
	bucket_limit = 30;
	cache_limit  = hashsize * bucket_limit;
	cache_count  = 0;
	// Default timeout for flows: 32 seconds.
	lifetime     = Timestamp(32.0);
	//hashlock     = RW_LOCK_UNLOCKED;

	int size = hashsize * sizeof(struct ipmp_flow_head);
	int i;
	if((hashbase = (struct ipmp_flow_head*)malloc(size)) != NULL) {
		for(i=0; i<512; i++) {
			hashbase[i].length = 0;
			hashbase[i].head   = NULL;
			hashbase[i].tail   = NULL;
		}
	}
}


IPMP::FlowCache::~FlowCache()
{
}


/*
 * unlink
 *
 * pre: lock on hashlock held
 */
void IPMP::FlowCache::unlink(struct ipmp_flow *f, struct ipmp_flow_head *ifh)
{
	if(ifh->head == f) {
		if(ifh->tail == f) {
			ifh->head = ifh->tail = NULL;
		} else {
			ifh->head = ifh->head->next;
			ifh->head->prev = NULL;
		}
	} else if(ifh->tail == f) {
		  ifh->tail = ifh->tail->prev;
		  ifh->tail->next = NULL;
	} else {
		  f->next->prev = f->prev;
		  f->prev->next = f->next;
	}

	return;
}


/*
 * handle_timeout
 * ISO C++ forbids taking a pointer to a non-static function, so we have to
 * have one static handle_ method and one function that does the work
 * (see timeout())
 */
void IPMP::FlowCache::handle_timeout(Timer* timer, void* data)
{
	timer_data* td = (timer_data*)data;
	if (!td) return;
	td->fc->timeout(td);

	timer->clear();
	delete timer;
}


/*
 * timeout
 *
 *
 */
void IPMP::FlowCache::timeout(struct timer_data* td)
{
	if (!td) return;
	struct ipmp_flow      *f   = (struct ipmp_flow *)td->flow;
	struct ipmp_flow_head *ifh = &td->fc->hashbase[f->key];

	// write_lock_bh(&ifc.hashlock);

	unlink(f, ifh);
	ifh->length--;
	cache_count--;

	free(f);
	free(td);

	// write_unlock_bh(&ifc.hashlock);
}


/*
 * hashid
 *
 */
unsigned int IPMP::FlowCache::hashid(struct ipmp_flow_key *key)
{
	unsigned int hashid = hashsecret ^ key->id ^
		key->src ^ (key->src >> 16) ^
		key->dst ^ (key->dst >> 16);

	return hashid & hashmask;
}


/*
 * lookup
 *
 * look for an ipmp_flow object based on the ip->src,dst and ipmp->id
 * if we don't find an entry, try and add one.
 *
 * pre: lock on hashlock held
 */
struct ipmp_flow* IPMP::FlowCache::lookup(struct ipmp_flow_key *key,
					  struct ipmp_flow_head **ifhp)
{
	struct ipmp_flow_head *ifh;
	struct ipmp_flow      *f;

	ifh = &hashbase[hashid(key)];
	*ifhp = ifh;

	for(f = ifh->head; f != NULL; f = f->next) {
		if(key->src == f->src && key->dst == f->dst && key->id == f->id)
			return f;
	}

	return NULL;
}


/*
 * tail
 *
 * pre: lock on hashlock held
 */
void IPMP::FlowCache::tail(struct ipmp_flow *f, struct ipmp_flow_head *ifh)
{
	if(ifh->tail != NULL) ifh->tail->next = f;
	else		  ifh->head = f;

	f->prev = ifh->tail;
	ifh->tail = f;
	f->next = NULL;

	return;
}


/*
 * drop
 *
 * for this function to work, the flow must be in the list pointed to by
 * ifh.  if it is not, it will dereference a null pointer
 *
 * pre: write_lock on hashlock held
 */
void IPMP::FlowCache::drop(struct ipmp_flow *f, struct ipmp_flow_head *ifh)
{
	//del_timer(&f->timer);
	delete f->timer;

	unlink(f, ifh);

	ifh->length--;
	cache_count--;

	//kmem_cache_free(ifc.cache, f);
	free(f);

	return;
}


/*
 * flowc_get
 *
 *
 */
u8 IPMP::FlowCache::flowc_get(u32 src_addr, u32 dst_addr, u16 ipmp_id)
{
	if(parent->sysctl_flowc == false)
		return 0;

	struct ipmp_flow_key _key;
	_key.src = src_addr;
	_key.dst = dst_addr;
	_key.id  = ipmp_id;
	struct ipmp_flow_key* key = &_key;

	struct ipmp_flow_head *ifh;
	struct ipmp_flow      *f;
	u8		     flowc;

	//  write_lock_bh(&ifc.hashlock);

	if((f = lookup(key, &ifh)) != NULL) {
		/* shunt this entry to the end of the list */
		unlink(f, ifh);
		tail(f, ifh);

		/* reset the callout */
		// mod_timer(&f->timer, jiffies + (ifc.lifetime * HZ));
		f->timer->schedule_after(lifetime);

		flowc = ++f->flowc;
		// write_unlock_bh(&ifc.hashlock);
		return flowc;
	}

	/*
	 * this bucket is full, but we need to add a new entry.
	 * drop the first entry in this bucket - the oldest unused entry
	 */
	if(ifh->length == bucket_limit) {
		f = ifh->head;
		drop(f, ifh);
	}

	if((f = (struct ipmp_flow*)malloc(sizeof(*f))) == NULL) {
	//      write_unlock_bh(&ifc.hashlock);
		return 0;
	}

	memset(f, 0, sizeof(struct ipmp_flow));
	f->src = key->src;
	f->dst = key->dst;
	f->id  = key->id;
	f->key = hashid(key);

	/* insert the new node at the tail of the list */
	tail(f, ifh);
	ifh->length++;
	cache_count++;

	/* schedule a timer for expiration of the flow */
	struct timer_data* td;
	if((td = (struct timer_data*)malloc(sizeof(*td))) == NULL) {
		return 0;
	}
	td->fc = this;
	td->flow = f;

	f->timer = new Timer(&IPMP::FlowCache::handle_timeout, (void*)td);
	f->timer->initialize(parent);
	f->timer->schedule_after(lifetime);

	//  write_unlock_bh(&ifc.hashlock);

	return 0;
}


CLICK_ENDDECLS
EXPORT_ELEMENT(IPMP)
