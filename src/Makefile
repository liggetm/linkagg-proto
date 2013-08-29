CC			= gcc
DIRPFRING	= ./thirdParty/pfring
INCLUDE		= -I ${DIRPFRING}/kernel -I ${DIRPFRING}/libpcap
LINKS		= -lpthread -lrt
CFLAGS		= -Wall ${INCLUDE} -O2 
LIBPFRING	= ${DIRPFRING}/lib/libpfring.a
LIBPCAP		= ${DIRPFRING}/libpcap/libpcap.a
LIBS		= ${LIBPFRING} ${LIBPCAP}

all: kernel-mod libpfring libpcap linkaggtx

kernel-mod:
	cd ${DIRPFRING}/kernel && \
	$(MAKE)

libpfring:
	cd ${DIRPFRING}/lib && \
	/bin/bash ./configure && \
	$(MAKE)

libpcap:
	cd ${DIRPFRING}/libpcap && \
	/bin/bash ./configure && \
	$(MAKE)

linkaggtx: linkaggtx.o ${LIBPFRING}
	${CC} ${CFLAGS} ${LINKS} linkaggtx.o ${LIBS} -o $@
	
clean:
	/bin/rm -f *.o linkaggtx
	cd ${DIRPFRING}/lib && \
	$(MAKE) clean
	cd ../../../
	cd ${DIRPFRING}/kernel && \
	$(MAKE) clean
	cd ../../../
	cd ${DIRPFRING}/libpcap && \
	$(MAKE) clean