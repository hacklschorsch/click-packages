/**
 * Ssr-AnsiC wrapper for using SSR in the click modular router.
 * This version features IPMP for measurement.
 * Florian Sesser 2010.
 * Thomas Furhmann Research Group, TUM, 2010.
 */

// require("ssr");
// require("ipmp");


// ADDRESS INFORMATION

AddressInfo(
	ssr_dev	192.168.231.1/24
);


// DEVICE SETUP

tun :: KernelTun(ssr_dev, DEVNAME ssr, MTU 1300);
eth_in :: FromDevice(wl0);
eth_out :: ToDevice(wl0);


// SSR WITH IPMP
/*
 * This compound element uses the same input/output ports the
 * SsrWrapperElement alone uses, but sports an IPMP measurement
 * element and DecIPTTL elements.
 *
 * This eases the integration into larger setups.
 *
 * [0] in/out ports (lower layer): IP in SSR in Ethernet
 * [1] in/out ports (upper layer): IP send and receive
 */
elementclass SsrWithIPMP {

	// SSR WRAPPER INITIALIZATION
	ssr_wrap :: SsrWrapperElement(SSR_ADDR ssr_dev, NIC_ADDR wl0:eth);

	// upper layer
	input[1] -> [1]ssr_wrap[1] -> [1]output;

	// lower layer
	input[0] ->
	stripeth :: Strip(14) ->
		stripssr :: StripSSRHeader ->
			// 0 = IPMP, 1 = IP
			innercl :: Classifier(9/A9, -) ->
				// Here: IPMP in IP in SSR
				MarkIPHeader ->
				DecIPTTL ->
				// IPMP Out 0: forwarded IPMP packets
				ipmpel :: IPMP(ssr_dev) ->
		unstripssr :: UnstripSSRHeader ->
	unstripeth :: Unstrip(14) ->
	ssr_wrap ->
	[0]output;

				// IPMP Out 1: Received IPMP replies
				ipmpel[1] -> unstripssr;

				// IPMP Out 2: Replies from this machine
				/*
				 * SSR needs our IPMP Echo replies because of
				 * the SSR control information in the SSR
				 * header part of the IPMP request. But to send
				 * out the reply, we also have to copy it into
				 * the [1]ssr_wrap SSR send_payload input port.
				 */
				ipmpel[2] -> ipmptee :: Tee;
				ipmptee[0] -> [1]ssr_wrap;
				ipmptee[1] -> unstripssr;

			innercl[1] ->
				// Here: IP in SSR
				MarkIPHeader ->
				DecIPTTL ->
				unstripssr;

		// SSR control (non-payload) traffic goes into [0]SSR
		stripssr[1] -> unstripssr;
};
// instantiate the ElementClass
ssr_with_ipmp :: SsrWithIPMP;


// CLICK CONFIGURATION

/* All IP Datagrams that go into tun are sent to SendPayload.
 * This works b/c the Linux kernel processes packets to the
 * local host by itself - So we need no further filtering.
 */
tun ->
	[1]ssr_with_ipmp[1] ->
	CheckIPHeader ->
	tun;

/* In this implementation, SSR packets are encapsulated in ethernet frames
 * with the EtherType field containing the value "0x5512" ("5512" looks
 * like "SSR" if you try really hard).  */
eth_in ->
	ethcl :: Classifier(12/5512) ->
	ssr_with_ipmp ->
	qe :: Queue ->
	eth_out;

// EOF.
