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






