linkagg-proto
=============

Experimental link aggregation features project.

--- Pre-reqs ---
yum install libpcap libpcap-devel kernel-devel


--- Build ---
cd src/
sh build.sh

--- Run ---
Before running any binaries the pfring kernel modules must be loaded:

cd src/
insmod thirdParty/pfring/kernel/pf_ring.ko

If the module was successfully installed you should now be able to run any
binaries in the src directory.
