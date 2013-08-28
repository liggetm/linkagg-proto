CC			= gcc
INCLUDE		= -I thirdParty/pfring/kernel -I thirdParty/pfring/libpcap
LINKS		= -lpthread -lrt
CFLAGS		= -Wall ${INCLUDE} -O2 
LIBPFRING	= ./thirdParty/pfring/lib/libpfring.a
LIBPCAP		= ./thirdParty/pfring/libpcap/libpcap.a
LIBS		= ${LIBPFRING} ${LIBPCAP}

all: kernel-mod libpfring libpcap pfcount pfsend

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
	
pfcount: pfcount.o ${LIBPFRING}
	${CC} ${CFLAGS} ${LINKS} pfcount.o ${LIBS} -o $@
	
pfsend: pfsend.o ${LIBPFRING}
	${CC} ${CFLAGS} ${LINKS} pfsend.o ${LIBS} -o $@
	
clean:
	/bin/rm -f pfcount.o pfcount
	/bin/rm -f pfsend.o pfsend
	cd thirdParty/pfring/lib && \
	$(MAKE) clean
	cd ../../../
	cd thirdParty/pfring/kernel && \
	$(MAKE) clean
	cd ../../../
	cd thirdParty/pfring/libpcap && \
	$(MAKE) clean