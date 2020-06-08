#include "IPv4.h"

using namespace zeek::llanalyzer::IPv4;

IPv4Analyzer::IPv4Analyzer()
	: zeek::llanalyzer::Analyzer("IPv4Analyzer")
	{
	}

std::tuple<zeek::llanalyzer::AnalyzerResult, zeek::llanalyzer::identifier_t> IPv4Analyzer::Analyze(Packet* packet)
	{
	packet->l3_proto = L3_IPV4;
	packet->hdr_size = (packet->cur_pos - packet->data);

	// Leave LL analyzer land
	return std::make_tuple(AnalyzerResult::Terminate, 0);
	}