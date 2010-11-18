#ifndef SAMPLEPACKAGEELEMENT_HH
#define SAMPLEPACKAGEELEMENT_HH
#include <click/element.hh>
CLICK_DECLS

/*
 * =c
 *
 * IPMP(ADDR [, I<KEYWORDS>])
 *
 * =s ipmp
 *
 * IP Measurement Protocol
 *
 * =d
 *
 * This element aims to implement the core of the IP Measurement protocol as
 * defined in McGregor and Luckie's Experimental Internet Draft
 * draft-mcgregor-ipmp-05.txt of June 05, 2006. See
 * http://www.wand.net.nz/~mluckie/pubs/mluckie-thesis.pdf .
 *
 * This module expects IPMP packets with Ethernet preamble, IP address
 * annotations set (packets without are dropped, or pushed to port 3, if it
 * exists).
 *
 * Outputs (all push):
 *
 * Port 0: Forwarded IPMP packets
 * Port 1: IPMP replies to this machine
 * Port 2: IPMP replies from this machine (Beware: May need special handling
 *         like ARPQuerier or LinuxIPLookup for routing)
 * Port 3 (optional): Dropped packets, if connected.
 *
 *
 * Note: You probably also want to decrement the IP TTL value when the IPMP
 * packet passes through this element. This element does not touch the TTL
 * value.  Use the DecIPTTL element for that.
 *
 * Arguments are:
 *
 * =over 5
 *
 * =item ADDR
 *
 * Mandatory. The IPv4 address to stamp into the payload of IPMP packets.
 * Should be a routable, unique address that identifies this router, so it
 * can be used to identify router aliases.
 *
 * Also is used to identify if the incoming packet is destined at this
 * router, i.e. if we have to forward it or reply to it.
 *
 * =item IPHCHK
 *
 * Optional. Boolean. True by default. Determins if the IP header
 * is checksummed on receive. Bad packets are dropped.
 *
 * =item PAYLOADCHK
 *
 * Optional. Boolean. True by default. Determines if the IPMP payload
 * is checksummed on receive. Bad packets are dropped.
 *
 * =item DEBUG
 *
 * Optional. Boolean. False by default. Outputs debugging information
 * via click_chat() if true. Bad packets are dropped.
 *
 * =item FLOWC
 *
 * Optional. Boolean. True by default. Determines if statistics on IPMP flows
 * are to be kept. The mechanism is counting subsequent IPMP Echo
 * packets. Flows timeout after 32 seconds.
 *
 * =back
 *
 * =a CheckIPHeader, MarkIPHeader, DecIPTTL
 * 
 */

#include <clicknet/ip.h>

extern "C" {
#include "ipmp_proto.hh"
}


class IPMP : public Element { public:

	/*
	 * usual Click Element boilerplate
	 */

	IPMP();
	~IPMP();

	const char* class_name() const { return "IPMP"; }
	const char* port_count() const { return "1/3-4"; }
	const char* processing() const { return PUSH; }

	int configure(Vector<String>& conf, ErrorHandler* errh);
	int initialize(ErrorHandler *errh);

	void push(int port, Packet* p);


	/*
	 * IPMP specifics
	 */

	// Address we use when adding Path Records:
	IPAddress IPv4Address;

	// Storage for IPMP flows
	class FlowCache : public ipmp_flowcache {
	private:
		IPMP* parent;
	public:
		FlowCache(IPMP* parent);
		~FlowCache();

		u8 flowc_get(u32 src_addr, u32 dst_addr, u16 ipmp_id);

		/* flow counting routines & the supporting hash map */
		void unlink(struct ipmp_flow *f, struct ipmp_flow_head *ifh);
		unsigned int hashid(struct ipmp_flow_key *key);
		struct ipmp_flow* lookup(struct ipmp_flow_key *key,
						struct ipmp_flow_head **ifhp);
		void tail(struct ipmp_flow *f, struct ipmp_flow_head *ifh);
		void drop(struct ipmp_flow *f, struct ipmp_flow_head *ifh);

		/* flow timeout */
		struct timer_data {
			FlowCache* fc;
			struct ipmp_flow* flow;
		};
		static void handle_timeout(Timer*, void* data); // callback
		void timeout(struct timer_data*); // called by callback
	} ifc;

	/*
	 * the following sysctl's determine if a check will be made on
	 * an IPMP packet before any modifications are made.  they are
	 * initialised to reasonable defaults.
	 */
	bool sysctl_ipheader_cksum;
	bool sysctl_payload_cksum;
	bool sysctl_debug;
	bool sysctl_flowc;

	/* helpers */
	int ipmp_insertpathrecord(WritablePacket *skb,u32 addr,u8 ttl,u8 flowc);
	u16 ipmp_pr(struct ipmp_pathrecord *pr, u32 addr, Timestamp ts,
			u8 ttl, u8 flowc);

	/* process IPMP pkts */
	void ipmp_handle_echoreply(WritablePacket *skb);
	void ipmp_handle_echorequest(WritablePacket *skb_in);
	void ipmp_forward(WritablePacket *skb);
};



CLICK_ENDDECLS
#endif
