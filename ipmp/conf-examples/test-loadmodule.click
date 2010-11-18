/* Test if the Click IPMP module loads successfully */

// require(package "ipmp");

test :: IPMP(eth0:ip);

Idle -> test;			// input (IPv4 elements, preferably IPMP only)
test[0] -> d :: Discard;	// output forwarded packets,
test[1] -> d;			// received replies (for the local host),
test[2] -> d;			// sending replies (for the querying host),
test[3] -> d;			// packets failing the input checking

DriverManager(stop);

