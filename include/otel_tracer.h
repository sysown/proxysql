#ifndef __CLASS_PROXYSQL_OTEL_TRACER_H
#define __CLASS_PROXYSQL_OTEL_TRACER_H

#include <cstddef>
#include <cstdint>
#include <memory>

#include "opentelemetry/nostd/shared_ptr.h"
#include "opentelemetry/trace/tracer.h"
#include "opentelemetry/sdk/resource/resource.h"
#include "opentelemetry/exporters/otlp/otlp_environment.h"

#include "proxysql.h"
#include "unsafe_shared_ptr.h"
#include "otel_span.h"

namespace otel_nostd = opentelemetry::nostd;
namespace otel_trace_api = opentelemetry::trace;
namespace otel_resource = opentelemetry::sdk::resource;
namespace otel_exporter = opentelemetry::exporter::otlp;

using std::string;
using opentelemetry::trace::Span;
using opentelemetry::trace::Scope;

using OTelSpanCtx = opentelemetry::trace::SpanContext;
using OTelSpanAttrVal = opentelemetry::common::AttributeValue;

class OTelTracer {
public:
	OTelTracer();
	~OTelTracer();

	void Setup();

	// Dependency injection support
	static OTelTracer* GetGlobalTracer();
	static void SetGlobalTracer(OTelTracer* tracer);
	bool IsTracerAvailable() const noexcept { return tracer != nullptr; }

	std::unique_ptr<OTelSpan> StartSpan(
		unsafe_shared_ptr<OTelSpanStack> stack,
		const char *__file,
		int __line,
		const char *name
	);

	const std::vector<string>& GetVariablesList();
	char *GetVariable(const char *var);
	bool SetVariable(const char *var, const char *val);
	std::set<std::string> GetFilter();
	void SetFilter(const std::set<std::string>& filter);

	void rdlock() { pthread_rwlock_rdlock(&rwlock); }
	void wrlock() { pthread_rwlock_wrlock(&rwlock); }
	void unlock() { pthread_rwlock_unlock(&rwlock); }
private:
	pthread_rwlock_t rwlock;

	otel_nostd::shared_ptr<otel_trace_api::Tracer> tracer;

	struct {
		bool trace_enable;
		string service_name;
		string resource_attributes;
		string exporter_otlp_protocol;
		string exporter_otlp_endpoint;
		string exporter_otlp_headers;
		string exporter_otlp_certificates;
		string exporter_otlp_compression;
		int64_t exporter_otlp_timeout;
		int64_t bsp_schedule_delay;
		size_t bsp_max_queue_size;
		size_t bsp_max_export_batch_size;
	} variables;

	bool span_filter_enable = false;
	std::set<std::string> span_filter;

	otel_trace_api::Tracer* get_tracer();
	bool allow_span(const char *__file, int __line, const char *name);
	otel_resource::ResourceAttributes get_resource_attributes();
	otel_exporter::OtlpHeaders get_otlp_headers();
	std::vector<std::pair<string, string>> parse_key_value_pairs(const string& input);
};

#endif  // __CLASS_PROXYSQL_OTEL_TRACER_H
