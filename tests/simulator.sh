#!/bin/bash
# # G_SLICE=always-malloc valgrind --leak-check=full --track-origins=yes --show-possibly-lost=yes ./mediaproxy-ng -t 0 -i $IP -l 25060 -f

pipe_o() {
	nc localhost 25060
}
pipe() {
	pipe_o > /dev/null
}
ip() {
	echo $(($RANDOM % 254 + 1)).$(($RANDOM % 254 + 1)).$(($RANDOM % 254 + 1)).$(($RANDOM % 254 + 1))
}
port() {
	echo $(($RANDOM % 64000 + 1024))
}

ids=""
for i in $(seq 1 1000); do
	callid=`uuid`
	test -z "$callid" && exit 1
	src=`ip`:`port`
	dst=`ip`:`port`
	gw=`ip`
	fromtag=`uuid`
	totag=`uuid`

	src_rel=`echo "request $callid $src:audio $gw voip.inode.at local unknown unknown unknown-agent info=domain:voip.sipwise.local,from:number@voip.inode.at,totag:,to:othernumber@voip.inode.at,fromtag:$fromtag" | pipe_o`
	dst_rel=`echo "lookup $callid $dst:audio $gw voip.inode.at local unknown unknown unknown-agent info=domain:voip.sipwise.local,from:number@voip.inode.at,totag:$totag,to:othernumber@voip.inode.at,fromtag:$fromtag" | pipe_o`
	echo "lookup $callid $dst:audio $gw voip.inode.at local unknown unknown unknown-agent info=domain:voip.sipwise.local,from:number@voip.inode.at,totag:$totag,to:othernumber@voip.inode.at,fromtag:$fromtag" | pipe
	echo version | pipe
	echo status | pipe

	echo foo > /dev/udp/${src_rel/ //}
	echo bar > /dev/udp/${dst_rel/ //}

	ids="$ids $callid"
done

sleep 10

for id in $ids; do
	echo "delete $id info=" | pipe
done
