# @TEST-DOC: Test deletion of elements in a broker backed table.
# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
#
# @TEST-EXEC: btest-bg-run manager-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff manager-1/.stdout

@load policy/frameworks/cluster/experimental

@TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["worker-1"] = [$node_type=Cluster::WORKER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2")), $manager="manager-1", $interface="eth0"],
};
@TEST-END-FILE

redef Log::default_rotation_interval = 0secs;

global t: table[string, count] of count &backend=Broker::MEMORY;

@if ( Cluster::local_node_type() == Cluster::WORKER )

event Cluster::Experimental::cluster_started()
	{
	print "Got cluster_started event";
	t["a", 1] = 12;
	t["b", 2] = 23;
	t["c", 3] = 42;

	delete t["b", 2];

	terminate();
	}

@else

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "Shutting down";
	print t;
	terminate();
	}

@endif
