#ifndef __CLASS_PROXYSQL_OTEL_SPAN_H
#define __CLASS_PROXYSQL_OTEL_SPAN_H

#include <cstddef>
#include <memory>
#include <signal.h>
#include <algorithm>
#include <utility>
#include <vector>

#include "opentelemetry/nostd/shared_ptr.h"
#include "opentelemetry/trace/span_context.h"
#include "opentelemetry/trace/tracer.h"
#include "opentelemetry/trace/span.h"
#include "opentelemetry/trace/span_startoptions.h"

#include "unsafe_shared_ptr.h"

#define OTEL_SPAN_STACK_SIZE_DEFAULT	8

namespace otel_trace_api = opentelemetry::trace;
namespace otel_common = opentelemetry::common;
namespace otel_nostd = opentelemetry::nostd;

using std::string;
using std::shared_ptr;
using otel_trace_api::Span;

using OTelSpanCtx = otel_trace_api::SpanContext;

/**
 * @brief RAII wrapper for OTelSpanCtx* to ensure memory safety
 *
 * This class ensures that OTelSpanCtx objects are properly managed
 * and don't leak when exceptions occur.
 */
class OTelSpanCtxWrapper {
private:
    OTelSpanCtx* ctx_;

public:
    // Constructor that takes ownership of an existing context
    explicit OTelSpanCtxWrapper(OTelSpanCtx* ctx = nullptr) : ctx_(ctx) {}

    // Constructor that creates a copy of the context
    explicit OTelSpanCtxWrapper(const OTelSpanCtx& ctx) : ctx_(nullptr) {
        try {
            ctx_ = new OTelSpanCtx(ctx);
        } catch (...) {
            // Memory allocation failed
            throw;
        }
    }

    // Destructor that cleans up the context
    ~OTelSpanCtxWrapper() {
        delete ctx_;
    }

    // Disable copying to avoid double deletion
    OTelSpanCtxWrapper(const OTelSpanCtxWrapper&) = delete;
    OTelSpanCtxWrapper& operator=(const OTelSpanCtxWrapper&) = delete;

    // Allow move operations
    OTelSpanCtxWrapper(OTelSpanCtxWrapper&& other) noexcept : ctx_(other.ctx_) {
        other.ctx_ = nullptr;
    }

    OTelSpanCtxWrapper& operator=(OTelSpanCtxWrapper&& other) noexcept {
        if (this != &other) {
            delete ctx_;
            ctx_ = other.ctx_;
            other.ctx_ = nullptr;
        }
        return *this;
    }

    // Access to the underlying context
    OTelSpanCtx* get() const noexcept { return ctx_; }
    OTelSpanCtx* operator->() const noexcept { return ctx_; }
    OTelSpanCtx& operator*() const noexcept { return *ctx_; }

    // Check if valid
    explicit operator bool() const noexcept { return ctx_ != nullptr; }

    // Release ownership and return raw pointer (caller takes ownership)
    OTelSpanCtx* release() noexcept {
        OTelSpanCtx* tmp = ctx_;
        ctx_ = nullptr;
        return tmp;
    }

    // Reset with a new context
    void reset(OTelSpanCtx* ctx = nullptr) {
        if (ctx != ctx_) {
            delete ctx_;
            ctx_ = ctx;
        }
    }
};
using OTelSpanAttrVal = otel_common::AttributeValue;

class OTelSpanStack {
private:
	std::vector<const OTelSpanCtx*> store;
	bool contains(const OTelSpanCtx* ctx);

public:
	OTelSpanStack(int capacity = OTEL_SPAN_STACK_SIZE_DEFAULT) { store.reserve(capacity); }
	~OTelSpanStack() = default;

	const OTelSpanCtx* GetCurrent();
	void Attach(const OTelSpanCtx* ctx);
	void Detach(const OTelSpanCtx* ctx);
	bool Contains(const OTelSpanCtx* ctx) { return contains(ctx); }
};

inline const OTelSpanCtx* OTelSpanStack::GetCurrent() {
	if (!store.empty())
		return store.back();
	else
	 	return nullptr;
}

inline void OTelSpanStack::Attach(const OTelSpanCtx* ctx) {
	if (!ctx)
		return;

	store.push_back(ctx);
}

inline void OTelSpanStack::Detach(const OTelSpanCtx* ctx) {
	if (!ctx || store.empty())
		return;

	// Normal case: pop the last span if it matches
	if (ctx->span_id() == store.back()->span_id()) {
		store.pop_back();
		return;
	}

	// Handle the anti-pattern where parent spans end before children
	// This is rare but we handle it gracefully to prevent crashes
	// Note: This may result in traces with incorrect parent-child relationships,
	// but it's better than crashing or leaving stale spans in the stack

	auto it = std::find_if(store.rbegin(), store.rend(),
		[ctx](const OTelSpanCtx* stored_ctx) {
			return ctx->span_id() == stored_ctx->span_id();
		});

	if (it != store.rend()) {
		// Remove all spans after the matched one (including the matched one)
		store.erase(it.base(), store.end());
	}

	// If no match found, the span wasn't in the stack.
	// This can happen in error scenarios, but we shouldn't crash.
}

inline bool OTelSpanStack::contains(const OTelSpanCtx* ctx) {
	if (!ctx)
		return false;

	for (auto it = store.rbegin(); it != store.rend(); ++it) {
		if (ctx->span_id() == (*it)->span_id()) {
			return true;
		}
	}
	return false;
}

class OTelSpan {
private:
	otel_nostd::shared_ptr<Span> span;
	OTelSpanCtxWrapper span_ctx;
	unsafe_shared_ptr<OTelSpanStack> ctx_stack;

	void create_span(
		otel_trace_api::Tracer* tracer,
		const string& name,
		const OTelSpanCtx* pctx
	);

public:
	OTelSpan() = default;
	OTelSpan(const OTelSpan&) = delete;
	OTelSpan& operator=(const OTelSpan&) = delete;
	OTelSpan(OTelSpan&&) = delete;
	OTelSpan& operator=(OTelSpan&&) = delete;

	explicit OTelSpan(
		otel_trace_api::Tracer* tracer,
		const string& name,
		const OTelSpanCtx* pctx = nullptr
	);

	explicit OTelSpan(
		otel_trace_api::Tracer* tracer,
		const string& name,
		unsafe_shared_ptr<OTelSpanStack> stack
	);

	~OTelSpan();

	void SetAttribute(const string& key, OTelSpanAttrVal value);
	void UpdateName(const string& name);

	// Access to span context for external use
	const OTelSpanCtx* GetContext() const noexcept { return span_ctx.get(); }
};

inline OTelSpan::OTelSpan(otel_trace_api::Tracer* tracer, const string& name, const OTelSpanCtx* pctx) {
	create_span(tracer, name, pctx);
}

inline OTelSpan::OTelSpan(otel_trace_api::Tracer* tracer, const string& name, unsafe_shared_ptr<OTelSpanStack> stack) {
	if (stack) {
		create_span(tracer, name, stack->GetCurrent());
		if (span_ctx) {
			stack->Attach(span_ctx.get());
			ctx_stack = stack;
		}
		return;
	}

	create_span(tracer, name, nullptr);
}

inline OTelSpan::~OTelSpan() {
	if (span && ctx_stack && span_ctx) {
		ctx_stack->Detach(span_ctx.get());
	}
	// RAII wrapper automatically handles span_ctx cleanup
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

inline void OTelSpan::create_span(otel_trace_api::Tracer* tracer, const string& name, const OTelSpanCtx* pctx) {
	try {
		otel_trace_api::StartSpanOptions option;

		if (pctx)
			option.parent = *pctx;

		span = tracer->StartSpan(name, option);
		span_ctx.reset(new OTelSpanCtx(std::move(span->GetContext())));
	} catch (...) {
		// If span creation fails, ensure we don't leave the object in an invalid state
		// Note: nostd::shared_ptr doesn't have reset(), so we'll just let the exception propagate
		// The span will be left in an invalid state, which is acceptable since construction failed
		throw;
	}
}

#endif  // __CLASS_PROXYSQL_OTEL_SPAN_H
