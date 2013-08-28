all: kernel-mod libpfring libpcap

kernel-mod:
	cd thirdParty/pfring/kernel && \
	$(MAKE)

libpfring:
	cd thirdParty/pfring/lib && \
	/bin/bash ./configure && \
	$(MAKE)

libpcap:
	cd thirdParty/pfring/libpcap && \
	/bin/bash ./configure && \
	$(MAKE)
	
clean:
	cd thirdParty/pfring/lib && \
	$(MAKE) clean
	cd ../../../
	cd thirdParty/pfring/kernel && \
	$(MAKE) clean
	cd ../../../
	cd thirdParty/pfring/libpcap && \
	$(MAKE) clean