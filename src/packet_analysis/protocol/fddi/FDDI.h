// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <packet_analysis/Analyzer.h>
#include <packet_analysis/Component.h>

namespace zeek::packet_analysis::FDDI {

class FDDIAnalyzer : public zeek::packet_analysis::Analyzer {
public:
	FDDIAnalyzer();
	~FDDIAnalyzer() override = default;

	AnalysisResultTuple Analyze(Packet* packet, const uint8_t*& data) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<FDDIAnalyzer>();
		}
};

}
