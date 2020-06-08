#pragma once

#include "AnalyzerSet.h"
#include "Config.h"
#include "dispatchers/Dispatcher.h"
#include "dispatchers/TreeMapDispatcher.h"
#include "dispatchers/UniversalDispatcher.h"
#include "dispatchers/UnorderedMapDispatcher.h"
#include "dispatchers/VectorDispatcher.h"

namespace zeek::llanalyzer {

class ProtocolAnalyzerSet : public AnalyzerSet {

public:
	explicit ProtocolAnalyzerSet(Config& configuration, const std::string& default_analyzer_name);
	~ProtocolAnalyzerSet() override;

	Analyzer* Dispatch(identifier_t identifier) override;
	void Reset() override;

protected:
	void DumpDebug() const override;

private:
	//    using dispatcher_impl = UnorderedMapDispatcher;
	//    using dispatcher_impl = VectorDispatcher;
	using dispatcher_impl = UniversalDispatcher;

	std::map<std::string, Analyzer*> analyzers;
	std::map<std::string, Dispatcher*> dispatchers;
	Dispatcher* root_dispatcher = nullptr;
	Dispatcher* default_dispatcher = nullptr;
	Dispatcher* current_state = nullptr;
	Analyzer* default_analyzer = nullptr;

	Dispatcher* GetDispatcher(Config& configuration, const std::string& dispatcher_name);
};

}