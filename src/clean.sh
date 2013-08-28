SRCPATH=$(pwd)

#######################################################
# Clean pfring library
#######################################################
cd thirdParty/pfring/lib
make clean
cd ${SRCPATH}

#######################################################
# Clean libpcap
#######################################################
cd thirdParty/pfring/libpcap-*
if [ -f Makefile ]; then
    make clean
fi
cd ${SRCPATH}

#######################################################
# Clean binaries
#######################################################
/bin/rm -f pfcount
