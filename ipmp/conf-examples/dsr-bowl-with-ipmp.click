// DSR Click configuration

// Some bugs fixed, DecIPTTL added, IPMP support added, tested on BOWL
// by Florian Sesser (TUM) <sesser@in.tum.de> 2010

//  Copyright 2002, Univerity of Colorado at Boulder.                        
//                                                                            
//                         All Rights Reserved                                
//                                                                            
//  Permission to use, copy, modify, and distribute this software and its    
//  documentation for any purpose other than its incorporation into a        
//  commercial product is hereby granted without fee, provided that the      
//  above copyright notice appear in all copies and that both that           
//  copyright notice and this permission notice appear in supporting         
//  documentation, and that the name of the University not be used in        
//  advertising or publicity pertaining to distribution of the software      
//  without specific, written prior permission.                              
//                                                                            
//  UNIVERSITY OF COLORADO DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS      
//  SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND        
//  FITNESS FOR ANY PARTICULAR PURPOSE.  IN NO EVENT SHALL THE UNIVERSITY    
//  OF COLORADO BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL         
//  DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING 
//  OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER       
//  TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR         
//  PERFORMANCE OF THIS SOFTWARE.                                            
//

ControlSocket(tcp, 9200);
ChatterSocket(tcp, 9201); 

// nsclick-raw-dsr.click
//
// This is a simple and stupid flat routing mechanism.
// It broadcasts ARP requests if it wants to find a destination
// address, and it responds to ARP requests made for it.

elementclass MyDSRRouter {
  $myaddr, $myaddr_ethernet |

  class :: Classifier(12/0806 20/0001, 12/0806 20/0002, -);
  myarpquerier :: ARPQuerier($myaddr,$myaddr_ethernet);
  myarpresponder :: ARPResponder($myaddr $myaddr_ethernet);
// fake device
  // th :: ToHost(tap2);
  // fh :: FromHost(tap2, $myaddr/16, ETHER $myaddr_ethernet);

  dsr_lt :: LinkTable(IP $myaddr);
  rt_q_dsr :: Queue(10); //for DSR data packets
  rt_q_data :: Queue(20); //for DSR routing packets
  arp_q :: Queue(20); //for ARP packets

  
  dsr_rt ::DSRRouteTable($myaddr, dsr_lt, OUTQUEUE rt_q_data, USE_BLACKLIST 1, DEBUG 0);
 
  //wlinfo :: WirelessInfo(SSID raw, BSSID 01:01:01:01:01:01,CHANNEL 2)	
  ethout :: PrioSched
        //-> WifiEncap(0x0, 00:00:00:00:00:00)
        //-> WifiEncap(0x0, WIRELESS_INFO wlinfo)
        // -> Print(out_mesh0)
        //-> ExtraEncap()
        -> ToDevice(mesh0);


   // Packets sent out by the kernel get pushed into the ARP query module
   kt::KernelTun($myaddr/16, DEVNAME tap2) // lol
   // fh
	// -> Print(frmkrn)
	// -> fromhost_cl :: Classifier(12/0806, 12/0800)[1]	// ARP reqs, IP
	// -> Strip(14)
        -> CheckIPHeader
        // -> IPPrint(fromkernel)
        -> GetIPAddress(16)
	-> cl_broadcasts_to_iface1 :: IPClassifier(dst 255.255.255.255, -)[1]
        -> [0]dsr_rt;

	cl_broadcasts_to_iface1[0]
		// -> IPPrint(Broadcast_To_Radio)
		-> myarpquerier; 

	// Reply to ARP reqs the kernel sends to the fake device.
	// fromhost_cl[0] -> ARPResponder(0.0.0.0/0 1:1:1:1:1:1) -> th;

 
  //Packets from device go through classifiers
  FromDevice(mesh0, SNIFFER false, PROMISC false)
	//-> ExtraDecap()
	//-> filtertx::FilterTX()
	// -> Print(in_mesh0)
	//-> WifiDecap()
	-> HostEtherFilter($myaddr_ethernet,1)
	// -> Print(to_class)
	-> class;

     

   //filtertx[1]->Print(Discard)->Discard;

  //there is another option, feed it back to 
  //routing table entry [2]

  // ARP queries from other nodes go to the ARP responder module
  class[0] -> myarpresponder;

  // ARP responses go to our query module
  class[1] -> [1]myarpquerier;



  // All other packets get checked to see if they're meant for us
  class[2]
  	// -> Print(non_arp)
        -> Strip(14)
        -> CheckIPHeader
        -> MarkIPHeader
        -> GetIPAddress(16)
	-> DecIPTTL // Flo: IP TTL == DSR TTL.
        -> DSR_class1::Classifier(09/C8,-); //Ckeck for DSR packets     


  //ARP responder packets are queued in arp_q and has a higher 
  //priority in the queue  
  myarpresponder
        // ->Print(arpresponse)
        ->arp_q;


  //DSR routing packets should go to input 1 of the DSR router
  DSR_class1[0]
	     // -> Print(dsr_class1)
	     -> StripDSRHeader
	     -> ipmpcl :: Classifier(9/A9, -) // IPMP, rest
	     	// IPMP Out 0: forwarded IPMP packets
		-> ipmpel :: IPMP(mesh0:ip)
		    -> dsr_unstrip::UnstripDSRHeader
		    -> [1]dsr_rt; // To DSR to be routed further
		// IPMP Out 1: Received IPMP replies
		ipmpel[1]
		    -> dsr_unstrip; // To DSR, which later feeds it to kernel
		// IPMP Out 2: Replies from this machine
		ipmpel[2]
		    -> [0]dsr_rt; // To DSR as a new IP packet
		// IPMP Out 3: Discard
		ipmpel[3]
		    -> Print("IPMP Discard") -> Discard;

	    ipmpcl[1]
		// Non-IPMP Unicast IP traffic
		-> dsr_unstrip;
            

  //IP packets go to input 0 of the DSR router
  DSR_class1[1]
             -> DropBroadcasts
             // -> Print(IPpacket)
             -> [0]dsr_rt;
   
  Idle -> [2]dsr_rt; //we do not care about this input


  //IP packets go to the kernel
  dsr_rt[0] -> CheckIPHeader
          // -> IPPrint(fromrouter)
          -> kt;
	  // -> EtherEncap(0x0800, 1:1:1:1:1:1, 2:2:2:2:2:2)
	  // -> th;

  //DSR routing  packets 
  dsr_rt[1] -> [0]myarpquerier;

  //DSR data packets 
  dsr_rt[2] -> [0]myarpquerier;
 
  // myarpquerier[0] -> DSR_class2::Classifier(09/C8,-); 
  myarpquerier[0] -> DSR_class2::Classifier(23/C8,-); 
  myarpquerier[1] -> arp_q;

  DSR_class2[0] // -> Print(DSRtoQueue)
                -> rt_q_dsr;

  DSR_class2[1] // -> Print(IP)
                -> rt_q_data;

   
   arp_q -> [0]ethout; 
   rt_q_dsr ->[1]ethout;
   rt_q_data ->[2]ethout;

}
  

//<IP address, interface address>
//AddressInfo(me_ip 192.168.32.1);
//AddressInfo(me_eth 00:0B:6B:84:B1:80);
//u :: MyDSRRouter(me_ip,me_eth);

u :: MyDSRRouter(mesh0:ip,mesh0:eth);

