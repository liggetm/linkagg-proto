linkagg-proto
=============

Experimental link aggregation prototype.


--- Pre-reqs ---
yum install libpcap libpcap-devel kernel-devel


--- Build ---
cd src/
sh build.sh


--- Run ---
*** Must be run as the root user ***

Before running any binaries the pfring kernel modules must be loaded:

cd src/
insmod thirdParty/pfring/kernel/pf_ring.ko

./pfcount -i <device>

If the module was successfully installed you should now be able to run any
binaries in the src directory.
 