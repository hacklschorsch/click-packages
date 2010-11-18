/* A 'complete' Click configuration for the IPMP module.
 *
 * This would be dead simple IF we would not
 * have to use routing and arp querying to
 * make this work in multi-hop environments.
 *
 * To try it, change the interface name from 'br-lan'
 * to whatever your interface is called.
 *
 * Florian Sesser, sesser@in.tum.de, 2010-09-28
 */

FromDevice(br-lan)
	-> cl :: Classifier(23/a9, 12/0806 20/0002)
	-> CheckIPHeader(OFFSET 14, VERBOSE true)
	-> IPPrint(chkip)
	-> ipmpel :: IPMP(br-lan:ip, DEBUG true)
	-> strnh :: StripToNetworkHeader
	-> LinuxIPLookup(br-lan)
	-> IPPrint(Lookup)
	-> aq :: ARPQuerier(br-lan:ip, br-lan:eth)
	-> Print(out)
	-> SimpleQueue
	-> ToDevice(br-lan);

cl[1]	-> [1]aq;
ipmpel[1] -> strnh;
ipmpel[2] -> strnh;
