#!/bin/bash

echo "Dependencies"

sudo apt-get update
sudo apt-get install iptables
sudo apt-get install autoconf
sudo apt-get install libtool
sudo apt-get install pkg-config
sudo apt-get install libmnl-dev

echo "Installing libnfnetlink and libnetfliter_queue"

cd	
mkdir libs
cd libs
git clone git://git.netfilter.org/libnfnetlink.git
git clone git://git.netfilter.org/libnetfilter_queue.git
cd libnfnetlink
./autogen.sh
./configure --prefix=/usr
make
sudo make install
sudo apt-get install libmnl-dev
cd ..
cd libnetfilter_queue
./autogen.sh
./configure --prefix=/usr
make
sudo make install

echo "Done!"


# Following commands are needed to start the agents. Hence commented
# TODO Create new file
#sudo docker run -i -t --privileged --rm hadoop_ele
#gcc -Wall -o test mahout_agent.c -lnfnetlink -lnetfilter_queue -lpthread
#sudo iptables -A OUTPUT -p ip -j NFQUEUE --queue-num 0
#iptables –flush
