#ifndef __CLASS_PROXYSQL_OTEL_SPAN_H
#define __CLASS_PROXYSQL_OTEL_SPAN_H

#include <memory>
#include <signal.h>
#include "unsafe_shared_ptr.h"
#include "otel_tracer.h"
#include "opentelemetry/nostd/shared_ptr.h"
#include "opentelemetry/trace/span.h"

extern OTelTracer *GloOTelTracer;

#define OTEL_SPAN_STACK_SIZE_DEFAULT	8

namespace otel_trace_api = opentelemetry::trace;
namespace otel_common = opentelemetry::common;
namespace otel_nostd = opentelemetry::nostd;

using std::string;
using otel_trace_api::Span;

using OTelSpanCtx = otel_trace_api::SpanContext;
using OTelSpanAttrVal = otel_common::AttributeValue;

class OTelSpanStack {
private:
	std::vector<OTelSpanCtx> store;
	bool contains(const OTelSpanCtx& ctx);

public:
	OTelSpanStack(int capacity = OTEL_SPAN_STACK_SIZE_DEFAULT) { store.reserve(capacity); }
	~OTelSpanStack() = default;

	OTelSpanCtx GetCurrent();
	void Attach(const OTelSpanCtx& ctx) { store.push_back(ctx); }
	void Detach(const OTelSpanCtx& ctx);
};

inline OTelSpanCtx OTelSpanStack::GetCurrent() {
	if (!store.empty())
		return store.back();
	else
	 	return OTelSpanCtx::GetInvalid();
}

inline void OTelSpanStack::Detach(const OTelSpanCtx& ctx) {
	if (store.empty())
		return;

	if (ctx == store.back()) {
		store.pop_back();
		return;
	}

	if (!contains(ctx)) {
		return;
	}

	// If this is reachable,
	// it means that there is a parent span which is getting out of scope before its child span.
	//
	// Example:
	// --------
	// - Function Fn1 starts a span based on a session object passed as a pointer argument.
	// - One of the child functions of Fn1 - Fn1_Child calls delete on the session object
	//   which in turn deallocates the session root span.
	// - So the root span ends before its children.
	//
	// Consequences:
	// -------------
	// 1. OTel spec doesn't talk about this. So, theoretically, it is okay to have a parent span that
	//    ends before its children.
	// 2. If OTel backend and trace visualizer tool we use doesn't supports this, then it is a problem.
	//    a) Even if we have support and we are able to visualize the trace, it might have incorrect
	//       parent-child relationships for part of or the entire trace.

	do {
		store.pop_back();
	} while(!(ctx == store.back()));

	store.pop_back();
}

inline bool OTelSpanStack::contains(const OTelSpanCtx& ctx) {
	for (auto it = store.rbegin(); it != store.rend(); ++it) {
		if (ctx == *it) {
			return true;
		}
	}
	return false;
}

class OTelSpan {
private:
	otel_nostd::shared_ptr<Span> span;
	unsafe_shared_ptr<OTelSpanStack> ctx_stack;
	bool create_span(const string& name, const OTelSpanCtx& pctx);
public:
	OTelSpan(const string& name, const OTelSpanCtx& pctx = OTelSpanCtx::GetInvalid());
	OTelSpan(const string& name, unsafe_shared_ptr<OTelSpanStack>& stack);
	~OTelSpan();

	void SetAttribute(const string& key, OTelSpanAttrVal value);
	void UpdateName(const string& name);
};

inline OTelSpan::OTelSpan(const string& name, const OTelSpanCtx& pctx) {
	create_span(name, pctx);
}

inline OTelSpan::OTelSpan(const string& name, unsafe_shared_ptr<OTelSpanStack>& stack) {
	if (stack) {
		if (create_span(name, stack->GetCurrent())) {
			stack->Attach(span->GetContext());
			ctx_stack = stack;
		}
		return;
	}

	create_span(name, OTelSpanCtx::GetInvalid());
}

inline OTelSpan::~OTelSpan() {
	if (span && ctx_stack) {
		ctx_stack->Detach(span->GetContext());
	}
}

inline void OTelSpan::SetAttribute(const string& key, OTelSpanAttrVal value) {
	if (span) {
		span->SetAttribute(key, value);
	}
}

inline void OTelSpan::UpdateName(const string& name) {
	if (span) {
		span->UpdateName(name);
	}
}

inline bool OTelSpan::create_span(const string& name, const OTelSpanCtx& pctx) {
	auto tracer = GloOTelTracer->get();
	if (!tracer)
		return false;

	auto option = otel_trace_api::StartSpanOptions();
	option.parent = pctx;
	span = tracer->StartSpan(name, option);

	return true;
}

#endif  // __CLASS_PROXYSQL_OTEL_SPAN_H
