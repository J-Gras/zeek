#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace llanalyzer { namespace LinuxSLL {

class LinuxSLLAnalyzer : public Analyzer {
public:
    LinuxSLLAnalyzer();
    ~LinuxSLLAnalyzer() override;

    std::tuple<AnalyzerResult, identifier_t> analyze(Packet* packet) override;

    static Analyzer* Instantiate() {
        return new LinuxSLLAnalyzer();
    }
private:
    struct SLLHeader {
        uint16_t packet_type;
        uint16_t arphrd_type;
        uint16_t addr_len;
        uint64_t addr;
        uint16_t protocol_type;
    } __attribute__((__packed__));
};

} }
