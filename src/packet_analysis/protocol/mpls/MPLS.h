// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <packet_analysis/Analyzer.h>
#include <packet_analysis/Component.h>

namespace zeek::packet_analysis::MPLS {

class MPLSAnalyzer : public zeek::packet_analysis::Analyzer {
public:
	MPLSAnalyzer();
	~MPLSAnalyzer() override = default;

	AnalysisResultTuple Analyze(Packet* packet, const uint8_t*& data) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<MPLSAnalyzer>();
		}
};

}