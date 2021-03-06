/*
 * leasepool.{cc,hh} -- track dhcp leases from a free pool
 * John Bicket
 *
 * Copyright (c) 2005 Massachusetts Institute of Technology
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

#include <click/config.h>
#include <click/error.hh>
#include <click/confparse.hh>
#include <click/etheraddress.hh>
#include <clicknet/ip.h>
#include <clicknet/udp.h>
#include <click/straccum.hh>
#include "leasepool.hh"
CLICK_DECLS

LeasePool::LeasePool()
{
}

LeasePool::~LeasePool()
{
}

void *
LeasePool::cast(const char *n) 
{
    if (strcmp(n, "DHCPLeasePool") == 0 || strcmp(n, "LeasePool") == 0)
	return (LeasePool *) this;
    else
	return DHCPLeaseTable::cast(n);
}

Lease *
LeasePool::new_lease_any(const EtherAddress &eth) 
{
	Lease *l = DHCPLeaseTable::rev_lookup(eth);
	if (l) {
		return l;
	}
	while (_free_list.size()) {
		IPAddress next = _free_list[0];
		_free_list.pop_front();
		if (_free.find(next)) {
			return new_lease(eth, next);
		}
	}
	return 0;
}

Lease *
LeasePool::new_lease(const EtherAddress &eth, IPAddress ip) 
{
	Lease *l = DHCPLeaseTable::rev_lookup(eth);
	if (l) {
		return l;
	}
	if (_free.get(ip)) {
		Lease l;
		l._eth = eth;
		l._ip = ip;
		l._start = Timestamp::now();
		l._end = l._start + Timestamp(60, 0);
		l._duration = l._end - l._start;
		insert(l);
		return lookup(ip);
	}
	return 0;
}

bool
LeasePool::insert(Lease l) {
	_free.erase(l._ip);
	return DHCPLeaseTable::insert(l);
}

void
LeasePool::remove(const EtherAddress &eth) {
	if (Lease *l = rev_lookup(eth)) {
		_free.set(l->_ip, l->_ip);
		_free_list.push_back(l->_ip);
	}
	return DHCPLeaseTable::remove(eth);	
}

int
LeasePool::configure( Vector<String> &conf, ErrorHandler *errh )
{
	if (cp_va_kparse(conf, this, errh,
			 "ETH", cpkP+cpkM, cpEthernetAddress, &_eth, 
			 "IP", cpkP+cpkM, cpIPAddress, &_ip,
			 "MASK", cpkP+cpkM, cpIPAddress, &_subnet,
			 "START", 0, cpIPAddress, &_start,
			 "END", 0, cpIPAddress, &_end,
			 cpEnd) < 0) {
		return -1;
	}
	for (uint32_t x = ntohl(_start.addr()); x < ntohl(_end.addr()); x++) {
		IPAddress ip = IPAddress(htonl(x));
		click_chatter("%s: inserting ip %s\n", __func__, ip.unparse().c_str());
		_free.set(ip, ip);
		_free_list.push_back(ip);
	}
	return 0;
}


EXPORT_ELEMENT(LeasePool LeasePool-LeasePool)
CLICK_ENDDECLS
