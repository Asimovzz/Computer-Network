#!/bin/bash

source topo.conf

function create_image()
{
	echo 'create_image()'
	echo create image node
	##########################################
	# your code here 
	##########################################
	docker image build -t node .
}

function create_nodes()
{
	echo 'create_nodes()'
	##########################################
	for h in ${nodes[@]}; do
		docker container create --cap-add NET_ADMIN --name $h node
    done
	##########################################
}


function run_nodes()
{
	echo 'run_node()'
	##########################################
	for h in ${nodes[@]}; do
		docker container start $h
	done
	##########################################
}

function create_links()
{
	echo 'create_links()'
	echo "expose each node's namespace"
	
	total=${#nodes[*]}
	echo there are $total nodes
	for ((i=0; i<$total; i=i+1)) do
		echo expose "${nodes[$i]}'s" namespace
	##########################################
	    pid=$(docker inspect -f '{{.State.Pid}}' ${nodes[$i]})
		ln -sf /proc/$pid/ns/net /var/run/netns/${nodes[$i]}
	##########################################
	done
	
	total=${#links[*]}
	echo there are $total items of \<node1 nic1 ip1 node2 nic2 ip2\>
	for ((i=0; i<$total; i=i+6)) do
		echo create the link for ${links[$i]} ${links[$i+1]} ${links[$i+2]} ${links[$i+3]} ${links[$i+4]} ${links[$i+5]}
	##########################################
	    node1=${links[$i]}
		nic1=${links[$i+1]}
		ip1=${links[$i+2]}
		node2=${links[$i+3]}
		nic2=${links[$i+4]}
		ip2=${links[$i+5]}

		# 创建 veth pair
		ip link add $nic1 type veth peer name $nic2
		
		# 配置一端 (node1)
		ip link set $nic1 netns $node1
		ip netns exec $node1 ip link set $nic1 up
		ip netns exec $node1 ip addr add $ip1 dev $nic1
		
		# 配置另一端 (node2)
		ip link set $nic2 netns $node2
		ip netns exec $node2 ip link set $nic2 up
		ip netns exec $node2 ip addr add $ip2 dev $nic2
	##########################################
	done
}


function stop_nodes()
{
	echo 'stop_nodes()'
	
	##########################################
	for h in ${nodes[@]}; do
		docker container stop $h
	done
	##########################################
}


function destroy_nodes()
{
	echo 'destroy_nodes()'
	for h in ${nodes[@]}; do
		echo destroy $h
	##########################################
	    docker container rm -f $h
		# 清理创建的网络命名空间软链接
		rm -f /var/run/netns/$h
	##########################################
	done
}
function destroy_image()
{
	echo 'destroy_image()'
	echo destroy image node
	##########################################
	docker image rm node
	##########################################
}

function configure_routes()
{
	echo 'configure_route()'
	# configure routers with ip_forward 1
	for h in ${nodes[@]}; do
		echo configure $h with ip_forward
	##########################################
	    docker exec -it $h bash -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
	##########################################
	done
	# add routing rules
	##########################################
	# h1 -> h2 (Long path: h1 -> r1 -> r2 -> r3 -> r5 -> h2)
	docker exec -it h1 route add -net 111.0.6.0 netmask 255.255.255.0 gw 111.0.0.2
	docker exec -it r1 route add -net 111.0.6.0 netmask 255.255.255.0 gw 111.0.1.2
	docker exec -it r2 route add -net 111.0.6.0 netmask 255.255.255.0 gw 111.0.2.2
	docker exec -it r3 route add -net 111.0.6.0 netmask 255.255.255.0 gw 111.0.3.2

	# h2 -> h1 (Short path: h2 -> r5 -> r4 -> r1 -> h1)
	docker exec -it h2 route add -net 111.0.0.0 netmask 255.255.255.0 gw 111.0.6.1
	docker exec -it r5 route add -net 111.0.0.0 netmask 255.255.255.0 gw 111.0.5.1
	docker exec -it r4 route add -net 111.0.0.0 netmask 255.255.255.0 gw 111.0.4.1
	##########################################
	# h1 -> h2 
	# h2 -> h1
}

case $1 in 
	"-ci")
		create_image
		;;
	"-cn")
		create_nodes
		;;
	"-rn")
		run_nodes
		;;
	"-cl")
		create_links
		;;
	"-sn")
		stop_nodes
		;;
	"-dn")
		destroy_nodes
		;;
	"-di")
		destroy_image
		;;
	"-cr")
		configure_routes
		;;
	*)
		echo "input error !"
		;;
esac

