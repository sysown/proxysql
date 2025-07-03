#ifndef __CLASS_PROXYSQL_OTEL_TRACER_H
#define __CLASS_PROXYSQL_OTEL_TRACER_H

#include "proxysql.h"
#include <cstdint>
#include "opentelemetry/nostd/shared_ptr.h"
#include "opentelemetry/trace/tracer.h"

namespace otel_nostd = opentelemetry::nostd;
namespace otel_trace_api = opentelemetry::trace;

using std::string;
using opentelemetry::trace::Span;
using opentelemetry::trace::Scope;

using OTelSpanCtx = opentelemetry::trace::SpanContext;
using OTelSpanAttrVal = opentelemetry::common::AttributeValue;

class OTelTracer {
public:
	OTelTracer();
	~OTelTracer();
	void setup();
	otel_trace_api::Tracer* get();
	const std::vector<string>& get_variables_list();
	bool has_variable(const char *var);
	char *get_variable(const char *var);
	bool set_variable(const char *var, const char *val);

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
};

#endif  // __CLASS_PROXYSQL_OTEL_TRACER_H
