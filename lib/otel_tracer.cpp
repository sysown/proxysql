#include <chrono>
#include <cstddef>
#include <cstdio>
#include <inttypes.h>
#include <memory>
#include <string>

#include "opentelemetry/trace/provider.h"
#include "opentelemetry/trace/tracer.h"
#include "opentelemetry/trace/span.h"
#include "opentelemetry/sdk/trace/tracer_provider_factory.h"
#include "opentelemetry/sdk/trace/batch_span_processor_factory.h"
#include "opentelemetry/exporters/otlp/otlp_http_exporter_factory.h"
#include "opentelemetry/exporters/otlp/otlp_http_exporter_options.h"

#include "gen_utils.h"
#include "otel_tracer.h"
#include "otel_span.h"

#define OTEL_TRACER_NAME_DEFAULT		"proxysql"
#define OTEL_SERVICE_NAME_DEFAULT		"proxysql"
#define OTEL_OTLP_PROTO_DEFAULT			"http/protobuf"
#define OTEL_OTLP_ENDPOINT_DEFAULT		"http://127.0.0.1:4318"
#define OTEL_OTLP_COMPRESSION_DEFAULT	"none"

// default values of opentelemetry-cpp-1.21.0
#define OTEL_OTLP_TIMEOUT_DEFAULT		10000
#define OTEL_BSP_SCHED_DELAY_DEFAULT	5000
#define OTEL_BSP_QUEUE_SIZE_DEFAULT		2048
#define OTEL_BSP_EXPORT_SIZE_DEFAULT	512

namespace otel_trace_sdk = opentelemetry::sdk::trace;

using std::string;

const std::vector<string> otel_variables = {
	"trace_enable",
	"trace_service_name",
	"trace_resource_attributes",
	"trace_exporter_otlp_protocol",
	"trace_exporter_otlp_endpoint",
	"trace_exporter_otlp_headers",
	"trace_exporter_otlp_certificates",
	"trace_exporter_otlp_compression",
	"trace_exporter_otlp_timeout",
	"trace_bsp_schedule_delay",
	"trace_bsp_max_queue_size",
	"trace_bsp_max_export_batch_size"
};

const std::vector<string> otlp_protocol = {
	"http/protobuf",
	// "http/json",
	// "grpc",
};

const std::vector<string> otlp_compression = {
	"none",
	"gzip"
};

OTelTracer::OTelTracer() : variables{} {
	pthread_rwlock_init(&rwlock,NULL);

	variables.service_name = OTEL_SERVICE_NAME_DEFAULT;
	variables.exporter_otlp_protocol = OTEL_OTLP_PROTO_DEFAULT;
	variables.exporter_otlp_endpoint = OTEL_OTLP_ENDPOINT_DEFAULT;
	variables.exporter_otlp_compression = OTEL_OTLP_COMPRESSION_DEFAULT;
	variables.exporter_otlp_timeout = OTEL_OTLP_TIMEOUT_DEFAULT;
	variables.bsp_schedule_delay = OTEL_BSP_SCHED_DELAY_DEFAULT;
	variables.bsp_max_queue_size = OTEL_BSP_QUEUE_SIZE_DEFAULT;
	variables.bsp_max_export_batch_size = OTEL_BSP_EXPORT_SIZE_DEFAULT;
}

OTelTracer::~OTelTracer() {
	pthread_rwlock_destroy(&rwlock);
}

void OTelTracer::Setup() {
	wrlock();

	// reset global trace provider
	std::shared_ptr<opentelemetry::trace::TracerProvider> none;
	otel_trace_api::Provider::SetTracerProvider(none);

	if (!variables.trace_enable) {
		unlock();
		return;
	}

	// configure exporter
	otel_exporter::OtlpHttpExporterOptions exporter_opt;
	exporter_opt.url = variables.exporter_otlp_endpoint;
	exporter_opt.compression = variables.exporter_otlp_compression;
	exporter_opt.timeout = std::chrono::milliseconds(variables.exporter_otlp_timeout);
	exporter_opt.ssl_ca_cert_path = variables.exporter_otlp_certificates;
	exporter_opt.http_headers = get_otlp_headers();
	auto exporter  = otel_exporter::OtlpHttpExporterFactory::Create(exporter_opt);

	// configure batch span processor
	otel_trace_sdk::BatchSpanProcessorOptions proc_opt;
	proc_opt.schedule_delay_millis = std::chrono::milliseconds(variables.bsp_schedule_delay);
	proc_opt.max_queue_size = variables.bsp_max_queue_size;
	proc_opt.max_export_batch_size = variables.bsp_max_export_batch_size;
	auto processor = otel_trace_sdk::BatchSpanProcessorFactory::Create(std::move(exporter), proc_opt);

	// configure service attributes
	auto resource = otel_resource::Resource::Create(get_resource_attributes());

	// setup tracer provider
	std::shared_ptr<otel_trace_api::TracerProvider> provider =
		otel_trace_sdk::TracerProviderFactory::Create(std::move(processor), std::move(resource));
	otel_trace_api::Provider::SetTracerProvider(provider);

	// create tracer object
	tracer = provider->GetTracer(OTEL_TRACER_NAME_DEFAULT);

	unlock();
}

const std::vector<std::string>& OTelTracer::GetVariablesList() {
	return otel_variables;
}

char * OTelTracer::GetVariable(const char* key) {
	char buf[21];

	if (strcasecmp(key,"trace_enable") == 0)
		return strdup(variables.trace_enable ? "true" : "false");

	if (strcasecmp(key,"trace_service_name") == 0)
		return strdup(variables.service_name.c_str());

	if (strcasecmp(key,"trace_resource_attributes") == 0)
		return strdup(variables.resource_attributes.c_str());

	if (strcasecmp(key,"trace_exporter_otlp_protocol") == 0)
		return strdup(variables.exporter_otlp_protocol.c_str());

	if (strcasecmp(key,"trace_exporter_otlp_endpoint") == 0)
		return strdup(variables.exporter_otlp_endpoint.c_str());

	if (strcasecmp(key,"trace_exporter_otlp_headers") == 0)
		return strdup(variables.exporter_otlp_headers.c_str());

	if (strcasecmp(key,"trace_exporter_otlp_certificates") == 0)
		return strdup(variables.exporter_otlp_certificates.c_str());

	if (strcasecmp(key,"trace_exporter_otlp_compression") == 0)
		return strdup(variables.exporter_otlp_compression.c_str());

	if (strcasecmp(key,"trace_exporter_otlp_timeout") == 0) {
		sprintf(buf, "%" PRId64, variables.exporter_otlp_timeout);
		return strdup(buf);
	}

	if (strcasecmp(key,"trace_bsp_schedule_delay") == 0) {
		sprintf(buf, "%" PRId64, variables.bsp_schedule_delay);
		return strdup(buf);
	}

	if (strcasecmp(key,"trace_bsp_max_queue_size") == 0) {
		sprintf(buf, "%zu", variables.bsp_max_queue_size);
		return strdup(buf);
	}

	if (strcasecmp(key,"trace_bsp_max_export_batch_size") == 0) {
		sprintf(buf, "%zu", variables.bsp_max_export_batch_size);
		return strdup(buf);
	}

	return nullptr;
}

bool OTelTracer::SetVariable(const char *key, const char *val) {
	if (strcasecmp(key,"trace_enable") == 0) {
		if (strcasecmp(val, "true") == 0 || strcasecmp(val, "1") == 0) {
			variables.trace_enable = true;
			return true;
		}
		if (strcasecmp(val, "false") == 0 || strcasecmp(val, "0") == 0) {
			variables.trace_enable = false;
			return true;
		}
		return false;
	}

	if (strcasecmp(key,"trace_service_name") == 0) {
		if (strlen(val) > 0) {
			variables.service_name = val;
			return true;
		}
		return false;
	}

	if (strcasecmp(key,"trace_resource_attributes") == 0) {
		variables.resource_attributes = val;
		return true;
	}

	if (strcasecmp(key,"trace_exporter_otlp_protocol") == 0) {
		for (auto& protocol : otlp_protocol) {
			if (strcasecmp(val, protocol.c_str()) == 0) {
				variables.exporter_otlp_protocol = val;
				return true;
			}
		}
		return false;
	}

	if (strcasecmp(key,"trace_exporter_otlp_endpoint") == 0) {
		if (strlen(val) > 0) {
			variables.exporter_otlp_endpoint = val;
			return true;
		}
		return false;
	}

	if (strcasecmp(key,"trace_exporter_otlp_headers") == 0) {
		variables.exporter_otlp_headers = val;
		return true;
	}

	if (strcasecmp(key,"trace_exporter_otlp_certificates") == 0) {
		variables.exporter_otlp_certificates = val;
		return true;
	}

	if (strcasecmp(key,"trace_exporter_otlp_compression") == 0) {
		for (auto& algo : otlp_compression) {
			if (strcasecmp(val, algo.c_str()) == 0) {
				variables.exporter_otlp_compression = val;
				return true;
			}
		}
		return false;
	}

	if (strcasecmp(key,"trace_exporter_otlp_timeout") == 0) {
		int64_t timeout = strtoll(val, NULL, 10);
		if (timeout > 0) {
			variables.exporter_otlp_timeout = timeout;
			return true;
		}
		return false;
	}

	if (strcasecmp(key,"trace_bsp_schedule_delay") == 0) {
		int64_t delay = strtoll(val, NULL, 10);
		if (delay > 0) {
			variables.bsp_schedule_delay = delay;
			return true;
		}
		return false;
	}

	if (strcasecmp(key,"trace_bsp_max_queue_size") == 0) {
		size_t qsize = strtol(val, NULL, 10);
		if (qsize > 0) {
			variables.bsp_max_queue_size = qsize;
			return true;
		}
		return false;
	}

	if (strcasecmp(key,"trace_bsp_max_export_batch_size") == 0) {
		size_t bsize = strtol(val, NULL, 10);
		if (bsize > 0) {
			variables.bsp_max_export_batch_size = bsize;
			return true;
		}
		return false;
	}

	return false;
}

void OTelTracer::SetFilter(const std::set<std::string>& filter) {
	wrlock();

	span_filter = filter;
	span_filter_enable = false;
	if(span_filter.size())
		span_filter_enable = true;

	unlock();
}

std::set<std::string> OTelTracer::GetFilter() {
	rdlock();
	auto ret = span_filter;
	unlock();

	return ret;
}

std::unique_ptr<OTelSpan> OTelTracer::StartSpan(
	unsafe_shared_ptr<OTelSpanStack> stack,
	const char *__file,
	int __line,
	const char *name
) {
	auto inactive_span = std::make_unique<OTelSpan>();

	rdlock();

	auto tracer = get_tracer();
	if (!tracer) {
		unlock();
		return inactive_span;
	}

	if(!allow_span(__file, __line, name)) {
		unlock();
		return inactive_span;
	}

	unlock();

	auto span = std::make_unique<OTelSpan>(tracer, name, stack);
	span->SetAttribute("code.file.path", __file);
	span->SetAttribute("code.line.number", __line);

	return span;
}

otel_trace_api::Tracer* OTelTracer::get_tracer() {
	if (variables.trace_enable) {
		return tracer.get();
	}

	return nullptr;
}

bool OTelTracer::allow_span(const char *__file, int __line, const char *name) {
	if (!span_filter_enable) {
		return true;
	}

	// full search - file:line:span_name
	std::string key(__file);
	key += ":" + std::to_string(__line);
	key += ":";
	key += name;
	if (span_filter.find(key) != span_filter.end()) {
		return true;
	}

	// partial - file:line:<empty>
	key = __file;
	key += ":" + std::to_string(__line);
	key += ":";
	if (span_filter.find(key) != span_filter.end()) {
		return true;
	}

	// partial - file:0:span_name
	key = __file;
	key += ":0:";
	key += name;
	if (span_filter.find(key) != span_filter.end()) {
		return true;
	}

	// partial - file:0:<empty>
	key = __file;
	key += ":0:";
	if (span_filter.find(key) != span_filter.end()) {
		return true;
	}

	return false;
}

otel_resource::ResourceAttributes OTelTracer::get_resource_attributes() {
	otel_resource::ResourceAttributes attributes{{"service.name", variables.service_name}};

	for (const auto& [key, value] : parse_key_value_pairs(variables.resource_attributes)) {
		attributes[key] = value;
	}

	return attributes;
}

otel_exporter::OtlpHeaders OTelTracer::get_otlp_headers() {
	otel_exporter::OtlpHeaders headers;

	for (const auto& [key, value] : parse_key_value_pairs(variables.exporter_otlp_headers)) {
		headers.insert({key, value});
	}

	return headers;
}

std::vector<std::pair<string, string>> OTelTracer::parse_key_value_pairs(const string& input) {
	std::vector<std::pair<string, string>> result;

	if (!input.empty()) {
		auto pairs = split_string(input, ',');
		for (const auto& pair : pairs) {
			auto kv = split_string(pair, '=');
			if (kv.size() == 2) {
				string key = trim(kv[0]);
				string value = trim(kv[1]);

				if (!key.empty()) {
					result.emplace_back(key, value);
				}
			}
		}
	}

	return result;
}
