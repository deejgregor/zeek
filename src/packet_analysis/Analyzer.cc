// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/Analyzer.h"

#include "zeek/DebugLogger.h"
#include "zeek/Dict.h"
#include "zeek/Event.h"
#include "zeek/RunState.h"
#include "zeek/session/Manager.h"
#include "zeek/Trace.h"
#include "zeek/util.h"

namespace zeek::packet_analysis
	{

Analyzer::Analyzer(std::string name, bool report_unknown_protocols)
	: report_unknown_protocols(report_unknown_protocols)
	{
	Tag t = packet_mgr->GetComponentTag(name);

	if ( ! t )
		reporter->InternalError("unknown packet_analysis name %s", name.c_str());

	Init(t);
	}

Analyzer::Analyzer(const Tag& tag)
	{
	Init(tag);
	}

void Analyzer::Init(const Tag& _tag)
	{
	tag = _tag;
	}

void Analyzer::Initialize()
	{
	default_analyzer = LoadAnalyzer("default_analyzer");
	}

zeek::packet_analysis::AnalyzerPtr Analyzer::LoadAnalyzer(const std::string& name)
	{
	auto& analyzer = zeek::id::find(GetModuleName() + name);
	if ( ! analyzer )
		return nullptr;

	auto& analyzer_val = analyzer->GetVal();
	if ( ! analyzer_val )
		return nullptr;

	return packet_mgr->GetAnalyzer(analyzer_val->AsEnumVal());
	}

const Tag Analyzer::GetAnalyzerTag() const
	{
	assert(tag);
	return tag;
	}

const char* Analyzer::GetAnalyzerName() const
	{
	assert(tag);
	return packet_mgr->GetComponentName(tag).c_str();
	}

bool Analyzer::IsAnalyzer(const char* name)
	{
	assert(tag);
	return packet_mgr->GetComponentName(tag) == name;
	}

AnalyzerPtr Analyzer::Lookup(uint32_t identifier) const
	{
	return dispatcher.Lookup(identifier);
	}

bool Analyzer::ForwardPacket(size_t len, const uint8_t* data, Packet* packet,
                             uint32_t identifier) const
	{
	auto span = zeek::trace::tracer->StartSpan("zeek::packet_analysis::Analzyer::ForwardPacket");
	auto scope = zeek::trace::tracer->WithActiveSpan(span);

	auto inner_analyzer = Lookup(identifier);
	if ( ! inner_analyzer )
		{
		for ( const auto& child : analyzers_to_detect )
			{
			if ( child->DetectProtocol(len, data, packet) )
				{
				DBG_LOG(DBG_PACKET_ANALYSIS,
				        "Protocol detection in %s succeeded, next layer analyzer is %s",
				        GetAnalyzerName(), child->GetAnalyzerName());
				inner_analyzer = child;
				break;
				}
			}
		}

	if ( ! inner_analyzer )
		inner_analyzer = default_analyzer;

	if ( ! inner_analyzer )
		{
		DBG_LOG(DBG_PACKET_ANALYSIS,
		        "Analysis in %s failed, could not find analyzer for identifier %#x.",
		        GetAnalyzerName(), identifier);

		if ( report_unknown_protocols )
			packet_mgr->ReportUnknownProtocol(GetAnalyzerName(), identifier, data, len);

		return false;
		}

	DBG_LOG(DBG_PACKET_ANALYSIS, "Analysis in %s succeeded, next layer identifier is %#x.",
	        GetAnalyzerName(), identifier);

	span->SetAttribute("analyzer", inner_analyzer->GetAnalyzerName());

		{
		std::ostringstream span_name;
		span_name << "(" << inner_analyzer->GetAnalyzerName() << " analyzer)::AnalyzePacket";
		auto analyzer_span = zeek::trace::tracer->StartSpan(span_name.str());
		auto analyzer_scope = zeek::trace::tracer->WithActiveSpan(span);
		return inner_analyzer->AnalyzePacket(len, data, packet);
		}
	}

bool Analyzer::ForwardPacket(size_t len, const uint8_t* data, Packet* packet) const
	{
	AnalyzerPtr inner_analyzer = nullptr;

	for ( const auto& child : analyzers_to_detect )
		{
		if ( child->DetectProtocol(len, data, packet) )
			{
			DBG_LOG(DBG_PACKET_ANALYSIS,
			        "Protocol detection in %s succeeded, next layer analyzer is %s",
			        GetAnalyzerName(), child->GetAnalyzerName());
			inner_analyzer = child;
			break;
			}
		}

	if ( ! inner_analyzer )
		inner_analyzer = default_analyzer;

	if ( ! inner_analyzer )
		{
		DBG_LOG(DBG_PACKET_ANALYSIS, "Analysis in %s stopped, no default analyzer available.",
		        GetAnalyzerName());

		if ( report_unknown_protocols )
			Weird("no_suitable_analyzer_found", packet);

		return false;
		}

	return inner_analyzer->AnalyzePacket(len, data, packet);
	}

void Analyzer::DumpDebug() const
	{
#ifdef DEBUG
	DBG_LOG(DBG_PACKET_ANALYSIS, "Dispatcher for %s", this->GetAnalyzerName());
	dispatcher.DumpDebug();
#endif
	}

void Analyzer::RegisterProtocol(uint32_t identifier, AnalyzerPtr child)
	{
	if ( run_state::detail::zeek_init_done )
		reporter->FatalError("Packet protocols cannot be registered after zeek_init has finished.");

	dispatcher.Register(identifier, std::move(child));
	}

void Analyzer::Weird(const char* name, Packet* packet, const char* addl) const
	{
	session_mgr->Weird(name, packet, addl, GetAnalyzerName());
	}

void Analyzer::AnalyzerConfirmation(session::Session* session, zeek::Tag arg_tag)
	{
	if ( session->AnalyzerState(arg_tag) == session::AnalyzerConfirmationState::CONFIRMED )
		return;

	session->SetAnalyzerState(GetAnalyzerTag(), session::AnalyzerConfirmationState::CONFIRMED);

	if ( ! analyzer_confirmation )
		return;

	const auto& tval = arg_tag ? arg_tag.AsVal() : tag.AsVal();
	event_mgr.Enqueue(analyzer_confirmation, session->GetVal(), tval, val_mgr->Count(0));
	}

void Analyzer::AnalyzerViolation(const char* reason, session::Session* session, const char* data,
                                 int len)
	{
	if ( ! analyzer_violation )
		return;

	session->SetAnalyzerState(GetAnalyzerTag(), session::AnalyzerConfirmationState::VIOLATED);

	StringValPtr r;

	if ( data && len )
		{
		const char* tmp = util::copy_string(reason);
		r = make_intrusive<StringVal>(util::fmt(
			"%s [%s%s]", tmp, util::fmt_bytes(data, std::min(40, len)), len > 40 ? "..." : ""));
		delete[] tmp;
		}
	else
		r = make_intrusive<StringVal>(reason);

	const auto& tval = tag.AsVal();
	event_mgr.Enqueue(analyzer_violation, session->GetVal(), tval, val_mgr->Count(0), std::move(r));
	}

	} // namespace zeek::packet_analysis
