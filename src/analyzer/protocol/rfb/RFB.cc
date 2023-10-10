#include "zeek/analyzer/protocol/rfb/RFB.h"

#include "zeek/Reporter.h"
#include "zeek/analyzer/protocol/rfb/events.bif.h"
#include "zeek/analyzer/protocol/tcp/TCP_Reassembler.h"

namespace zeek::analyzer::rfb {

RFB_Analyzer::RFB_Analyzer(Connection* c) : analyzer::tcp::TCP_ApplicationAnalyzer("RFB", c) {
    interp = new binpac::RFB::RFB_Conn(this);
    had_gap = false;
    invalid = false;
}

RFB_Analyzer::~RFB_Analyzer() { delete interp; }

void RFB_Analyzer::Done() {
    analyzer::tcp::TCP_ApplicationAnalyzer::Done();

    interp->FlowEOF(true);
    interp->FlowEOF(false);
}

void RFB_Analyzer::EndpointEOF(bool is_orig) {
    analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
    interp->FlowEOF(is_orig);
}

void RFB_Analyzer::DeliverStream(int len, const u_char* data, bool orig) {
    analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

    if ( TCP() && TCP()->IsPartial() )
        return;

    if ( had_gap )
        // If only one side had a content gap, we could still try to
        // deliver data to the other side if the script layer can handle this.
        return;

    if ( invalid )
        return;

    if ( interp->saw_handshake() && ! orig )
        // Don't try parsing server data after the handshake
        // (it's not completely implemented and contains mostly
        // uninteresting pixel data).
        return;

    try {
        interp->NewData(orig, data, data + len);
    } catch ( const binpac::Exception& e ) {
        AnalyzerViolation(util::fmt("Binpac exception: %s", e.c_msg()));
        invalid = true;
    }
}

void RFB_Analyzer::Undelivered(uint64_t seq, int len, bool orig) {
    analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
    had_gap = true;
    interp->NewGap(orig, len);
}

} // namespace zeek::analyzer::rfb
