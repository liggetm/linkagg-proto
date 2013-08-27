#!/bin/bash

PWD=$(pwd)

#######################################################
# Build pfring library
#######################################################
cd thirdParty/pfring/lib
make clean
./configure
make
cd ${PWD}

#######################################################
# Build libpcap
#######################################################
cd thirdParty/libpcap
make clean
./configure
make
cd ${PWD}






