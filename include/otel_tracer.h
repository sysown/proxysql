#ifndef CLASS_PROXYSQL_OTEL_TRACER_H
#define CLASS_PROXYSQL_OTEL_TRACER_H

#include "proxysql.h"
#include <cstdint>

using std::string;

class OTelTracer {
	public:
		OTelTracer();
		~OTelTracer();
		void init();
		void rdlock();
		void wrlock();
		void unlock();
		const std::vector<string>& get_variables_list();
		bool has_variable(const char *var);
		char *get_variable(const char *var);
		bool set_variable(const char *var, const char *val);
	private:
		pthread_rwlock_t rwlock;
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

#endif  // CLASS_PROXYSQL_OTEL_TRACER_H
