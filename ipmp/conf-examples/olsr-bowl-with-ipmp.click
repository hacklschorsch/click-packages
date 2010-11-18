ControlSocket(tcp, 9200,LOCALHOST true);
// Commented out: filled in by the node-controller
ChatterSocket(tcp, 9201); 


// Addresses: for MAC address: see
// https://bowl.net.t-labs.tu-berlin.de/projects/wiki/infrastructure/Addressing#Fake-MAC-addressing
// If commented out: filled in by the node-controller (uncomment for debugging)
//AddressInfo(fake 172.17.2.136/24 02:01:00:0F:88:19);
//AddressInfo(gw 172.17.2.1);

// Hardwired addresses
AddressInfo(panther 172.17.255.254/32);
//AddressInfo(fakearp 172.27.80.0/20 00:01:01:01:01:01); // Ruben: FIXME
AddressInfo(fakearp 00:01:01:01:01:01); // Ruben: FIXME
AddressInfo(localclient 172.17.242.2/24); // Used for debugging and
					  // configured to reply to
					  // ICMP ping, in the client
					  // range but on this local
					  // machine

// Generic TAP device, with arp responder
//
// Inputs: 
// [0] unicast ip
// [1] broadcast frames, ethernet
// Outputs
// [0] unicast ip 
// [1] ethernet frames that go directly out
elementclass HostDevice { 
        // Arguments are only the device name
	$device | 

	fh :: FromHost(DEVNAME $device, DST $device, ETHER $device:eth);
	th :: ToHost($device); 
	fh -> 
	// Classifier for incoming traffic
	// [0] arp request
	// [1] arp reply 
	// [2] broadcast
	// [3][4] dhcp 
	// [5] ip
	cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 0/ffffff, 34/0043, 36/0043, 12/0800);  
	
        // Arp requests got to the responder
	cl[0] -> ar::ARPResponder(0/0 fakearp) -> th; // Ruben: FIXME, check whether fakearp is the right thing to do

	// We don't ask for arp, hence replies are bogos
	cl[1] -> Discard; 

	// Broadcasts got to output 1
	cl[2] -> [1]output; 
        // Strip ethernet header and send to output 0
        cl[3] -> [1]output; cl[4]->[1]output; 
	cl[5] -> Strip(14) -> CheckIPHeader -> [0]output;  
	
        // Wrap ip packets in static mac and send to device
	aq :: EtherEncap(0x0800, fakearp:eth, $device:eth) -> th; // Ruben: FIXME, check whether fakearp is the right thing to do
	input[0] -> [0] aq; 

        // Send ethernet frames without touching them
	input[1] -> th; 
}


// Generic real device, with arp and ping responder
//
// Inputs: 
// [0] unicast ip
// [1] ethernet broadcasts
// Outputs
// [0] unicast ip 
// [1] ethernet directly out
elementclass IPDevice { 
        // Arguments as the device, promisc. mode(bool) and optional a net
	// which is answerd through arp 
	$device, $promisc, __REST__ $extra_arp_net | 
	td :: Queue -> ToDevice($device); 
        // We always run the pysical dev in promisc mode, 
        // it is filtered later... 
	FromDevice($device, SNIFFER false, PROMISC $promisc, HEADROOM 34) ->   
	// Print(from-$device-raw) -> 

	// Classifier for incoming traffic
	// [0] arp request
	// [1] arp reply 
	// [2] broadcast
	// [4] ip 
	cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 0/ffffff, 34/0043, 36/0043, 12/0800);  

        // ARP replies got the the ARPQuerier, its output goes directly out
	cl[1] -> [1]aq :: ARPQuerier($device, $device, BROADCAST $device:bcast) -> td;  
	// cl[1] -> Print(ar-response) -> [1]aq :: ARPQuerier($device, $device, BROADCAST $device:bcast) -> Print(aq-out) -> td;  

	// Input ip packets got to the ARPQuerier, which will care for
	// proper ethernet encap
	input[0] -> [0] aq; 

	// Forward broadcasts directly
	input[1] -> td;  

	// ARP queries are answered, extra_arp_net gives more ips to answer
	// with our own mac address
	cl[0] -> ar::ARPResponder($device $device, $extra_arp_net) -> td; 

	// Broadcasts are sent to output 1
	cl[2]->[1]output; 
        
        cl[3] -> [1]output; cl[4]->[1]output; 
	// ip packets from the device are stripped and send to output 0
        // sw:Switch can bypass the HostEtherFilter
	cl[5] -> 
//		Print(from-$device-ip) -> 
		st::Strip(14)->cip::CheckIPHeader->[0]output;  
}


// Generic "fake" tap device, with arp responder
//
// "Fake" implies the device is created without any IP address or MAC
// address. Hence an ifconfig up for the tap interface name is
// necessary
//
// Inputs: 
// [0] Unicast ip
// [1] Broadcast frames, ethernet
// Outputs
// [0] Unicast ip 
// [1] Ethernet frames that go directly out
// [2] Multicast
//
elementclass TapDevice {
  // The only argument is the device name
  $device |

  // Tap interface to the host. Achtung: we are not specifying any IP address nor MAC address,
    // hence you need to do an ifconfig $device up
  fh::FromHost($device);
  th::ToHost($device);

  fh // MAC address filtering
    ->HostEtherFilter($device:eth)
    // Classifier output
    // [0] ARP request
    // [1] ARP reply 
    // [2] Broadcast
    // [3] Multicast: range 01:00:5e:00:00:00 - 01:00:5e:7f:ff:ff
    // [4] ip
    ->cl::Classifier(12/0806 20/0001, 12/0806 20/0002, 0/ffffff, 0/01005e, 12/0800);

  // Output processing
  cl[0] // Answering ARP requests
    ->ar::ARPResponder($device)->th;

  cl[1] // ARP replies
    ->[1]aq::ARPQuerier($device)->th;

  cl[2]	// Broadcasts go to output 1
    -> [1]output;

  cl[3] // Multicast go to output 2
    ->Strip(14)->ckm::CheckIPHeader->[2]output;

  cl[4] // IP
    ->Strip(14)->ckip::CheckIPHeader->[0]output;

  ckm[1]->Print("Invalid IP header")->Discard;
  ckip[1]->Print("Invalid IP header")->Discard;

  // Input processing
  input[0] -> [0]aq;
  input[1] // Send ethernet frames without touching them
    -> th;
}
// End of compound elements configuration

// A minimum configuration only needs the tap_if, a ping responder
// attached behind and a routing table

// Instanciate devices
tap_if::TapDevice(tap0); // Fake tap device to be attached to the bridge
mesh_host_if::HostDevice(tap2); 
mesh_if :: IPDevice(mesh0,false);

// Useful elements
ping::ICMPPingResponder;
dump::Discard;

// Need a local routing table
mesh_loc_table::LinearIPLookup(
			       //172.17.242.254 172.17.255.101 3, // Needs to be dynamically added, local clients output.
			       // Typically, you do a "write
			       // mesh_loc_table.add 172.17.242.254/24
			       // some_IP 3" for all locally connected
			       // tunnels and do a more explicit
			       // "write mesh_loc_table.add
			       // 172.17.242.x/32 some_IP 3" for
			       // remote clients
			       tap0:ipnet 0,
			       panther gw:ip 1, // Panther always goes over the wire
			       0.0.0.0/0 gw:ip 1,
			       localclient:ip 2, // Local IP address, used for testing only
			       localclient:ipnet 4, // Complain if the client end point was not found
			       mesh0:ipnet 5 // Everything on the mesh goes to the mesh
			       );

mesh_loc_table[0]->[0]tap_if;
mesh_loc_table[1]->[0]tap_if;

// Fake tap interface input processing
tap_if[0]
->Print("Input")
// Sort out ICMP (IP proto 1) and IPinIP (IP proto 4) from everything else
->cl_tap::Classifier(09/01,09/04,-);

// Anwser ICMP requests on the fake tap interface
cl_tap[0]
->ping->mesh_loc_table;

// Process IPinIP packets
cl_tap[1]
->StripIPHeader->CheckIPHeader->Print("IPinIP")
->mesh_loc_table;

// Processing of local client IP address (see localclient above)
mesh_loc_table[2]->ping->mesh_loc_table;
mesh_loc_table[3]->IPEncap(ipip, tap0:ip, DST_ANNO)->SetIPChecksum->mesh_loc_table;
mesh_loc_table[4]->Print("Client not found")->Discard;
mesh_loc_table[5]//->Print("Off to the mesh")->Discard;
->mesh_if;

// Process non-ICMP input
cl_tap[2]->Discard;

// Filter out broadcast
tap_if[1]->Print("Broadcast")->dump;

// Filter out multicast
tap_if[2]->Print("Multicast")->dump;

// Non-ping packets (should not happen)
ping[1]->IPPrint("Only ICMP packets are supported")->dump;

// Let's deal with the mesh interfaces
mesh_route_table::LinearIPLookup(
				 tap2:net 0,
				 tap2:bcast 1, 
				 tap2:ip/32 1,
				 0/0 2,
				 );
//ttlmrt :: DecIPTTL; // For proper TTL processing
//ttlmrt[1] -> ICMPError(mesh0:ip, 11) -> mesh_route_table;
mesh_route_table[2]->IPPrint("Unknown dest.")->dump;

mesh_route_table[0]->mesh_if;

// Host output: packets coming from the OS mesh interface. Broadcast
// packets are not routed
mesh_host_if[0]->mcl::IPClassifier(dst host tap2:bcast, - );
mcl[0]->Print("Bcast")->mesh_if;
mcl[1]->mesh_route_table; 
mesh_host_if[1]->[1]mesh_if; // Typically, let OLSR packets go through
mesh_if[1]->[1]mesh_host_if;

// Host input: packets directly go into the mesh_route_table
// mesh_if->mesh_route_table;
// FLO: Packets do not go directly into the mesh_route_table but
//      instead are IPMP processed.
mesh_if[0]
	// IP and IP-in-IP Traffic
	-> DecIPTTL
	-> ipmpcl :: Classifier(9/A9, -) // IPMP, rest
		// IPMP Out 0: forwarded IPMP packets
		-> ipmpel :: IPMP(mesh0:ip)
			-> [0]mesh_route_table;
		// IPMP Out 1: Received IPMP replies
		ipmpel[1]
			-> [0]mesh_route_table;
		// IPMP Out 2: Replies from this machine
		ipmpel[2]
			-> [0]mesh_route_table;
		// IPMP Out 3: Discard
		ipmpel[3]
			-> Print("IPMP Discard") -> Discard;
	ipmpcl[1]
		// Non-IPMP Unicast IP traffic
		-> [0]mesh_route_table;


mesh_route_table[1]-> // Packets for the localhost. If IPIP,
		      // decapsulate and send further. Otherwise, off
		      // to the host mesh interface
ipipc :: IPClassifier(ip proto ipip, - )->
StripIPHeader->
CheckIPHeader->
mesh_loc_table;
ipipc[1] -> mesh_host_if;

// Unused input/output
Idle->[1]tap_if;
Idle->[0]mesh_host_if;
Idle->[0]mesh_if;

//FromDevice and ToDevice stuff
//for internal mesh communication

//Support for test traffic coming from wire
//It would have been encapsulated, so we have 
//to check for this

