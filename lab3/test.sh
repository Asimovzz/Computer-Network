#!/bin/bash

ns2=$(docker inspect -f '{{.State.Pid}}' n2)
ns3=$(docker inspect -f '{{.State.Pid}}' n3)

ip link delete n2-eth1 2>/dev/null
rm -f /var/run/netns/$ns3 2>/dev/null

ip link add n2-eth1 type veth peer name n3-eth0 

ip link set n2-eth1 netns $ns2
ip netns exec $ns2 ip link set n2-eth1 up
ip netns exec $ns2 ip addr add 10.0.1.1/24 dev n2-eth1

ln -s /proc/$ns3/ns/net /var/run/netns/$ns3
ip link set n3-eth0 netns $ns3
ip netns exec $ns3 ip link set n3-eth0 up
ip netns exec $ns3 ip addr add 10.0.1.2/24 dev n3-eth0