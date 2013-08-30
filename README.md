##  linkagg-proto ##
***

Experimental link aggregation prototype.


### Pre-reqs ###
  
yum install libpcap libpcap-devel kernel-devel  
  
  
### Build ###
  
cd src/  
sh build.sh  
  
  
### Run ###
* Must be run as the root user *  
  
Before running any binaries the pfring kernel modules must be loaded:  
  
cd src/  
insmod thirdParty/pfring/kernel/pf_ring.ko  
  
If the module was successfully installed you should now be able to run any
binaries in the src directory.
  
eg; Use linkaggtx to send 1 million packets of length 1500 bytes  
over eth1 and eth2. 
   
./linkaggtx -i eth1,eth2 -n 1000000 -l 1500  
  
