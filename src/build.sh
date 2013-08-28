#!/bin/bash

SRCPATH=$(pwd)

#######################################################
# Build pfring library
#######################################################
cd thirdParty/pfring/lib
./configure
make
cd ${SRCPATH}

#######################################################
# Build libpcap
#######################################################
cd thirdParty/pfring/libpcap
make clean
./configure
make
cd ${SRCPATH}

#######################################################
# Build pfcount
#######################################################
gcc -Wall -I thirdParty/pfring/ -I thirdParty/lib/ -I thirdParty/pfring/libpcap -O2 -lpthread -lrt pfcount.c ./thirdParty/pfring/lib/libpfring.a ./thirdParty/pfring/libpcap/libpcap.a -o pfcount








