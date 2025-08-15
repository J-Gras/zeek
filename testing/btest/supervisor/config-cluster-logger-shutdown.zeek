# @TEST-DOC: Verify logger writes all messages on shutdown.
#
# @TEST-PORT: SUPERVISOR_PORT
# @TEST-PORT: MANAGER_PORT
# @TEST-PORT: LOGGER_PORT
# @TEST-PORT: WORKER_PORT_1
# @TEST-PORT: WORKER_PORT_2
# @TEST-PORT: WORKER_PORT_3
# @TEST-PORT: WORKER_PORT_4
# @TEST-PORT: WORKER_PORT_5
# @TEST-PORT: WORKER_PORT_6
# @TEST-PORT: WORKER_PORT_7
# @TEST-PORT: WORKER_PORT_8
#
# @TEST-EXEC: btest-bg-run cluster zeek -B supervisor -j %INPUT
# @TEST-EXEC: btest-bg-wait 60
# @TEST-EXEC: tail cluster/logger/test.log > test.log
# @TEST-EXEC: btest-diff test.log

@load policy/frameworks/cluster/experimental

const NUM_WORKER = 8;

global topic = "supervisor-topic";
global supervisor_output_file: file;

# Disable log rotation
redef Log::default_rotation_interval = 0secs;

module Test;
export {
	redef enum Log::ID += { LOG };

	type Log: record {
		s: string;
	} &log;
}
module GLOBAL;

global worker_finished = 0;

event shutdown() &is_used
	{
	print "shutdown received";
	if ( Supervisor::is_supervisor() )
		terminate();
	else
		{
		if ( ++worker_finished < NUM_WORKER )
			return;

		Log::flush(Test::LOG);
		Broker::publish(topic, shutdown);
		}
	}

event zeek_init()
	{
	Log::create_stream(Test::LOG, [$columns=Test::Log]);

	if ( Supervisor::is_supervisor() )
		{
		Broker::subscribe(topic);
		Broker::listen("127.0.0.1", to_port(getenv("SUPERVISOR_PORT")));
		supervisor_output_file = open("supervisor.out");

		local cluster: table[string] of Supervisor::ClusterEndpoint;
		cluster["manager"] = [$role=Supervisor::MANAGER, $host=127.0.0.1,
			$p=to_port(getenv("MANAGER_PORT"))];
		cluster["logger"] = [$role=Supervisor::LOGGER, $host=127.0.0.1,
			$p=to_port(getenv("LOGGER_PORT"))];

		local i = 0;
		while ( ++i <= NUM_WORKER )
			{
			cluster[fmt("worker-%d", i)] = [$role=Supervisor::WORKER, $host=127.0.0.1,
				$p=to_port(getenv(fmt("WORKER_PORT_%d", i)))];
			}

		for ( n, ep in cluster )
			{
			local sn = Supervisor::NodeConfig($name = n);
			sn$cluster = cluster;
			sn$directory = n;
			sn$stdout_file = "stdout";
			sn$stderr_file = "stderr";

			local res = Supervisor::create(sn);

			if ( res != "" )
				print fmt("failed to create node %s: %s", n, res);
			}
		}
	else if ( Cluster::local_node_type() == Cluster::LOGGER )
		{
		Broker::subscribe(topic);
		Broker::peer("127.0.0.1", to_port(getenv("SUPERVISOR_PORT")));
		}
	}

@if ( Cluster::local_node_type() == Cluster::WORKER )

event Cluster::Experimental::cluster_started()
	{
	local i = 0;
	while ( ++i <= 1500000 )
		{
		Log::write(Test::LOG, [$s=fmt("test %s %s", Cluster::node, i)]);
		}

	Broker::flush_logs();
	Broker::publish(Cluster::logger_topic, shutdown);
	}

@endif
