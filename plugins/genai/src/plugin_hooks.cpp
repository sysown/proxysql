/**
 * @file plugin_hooks.cpp
 * @brief Adapter that bridges the plugin query-hook ABI to Anomaly_Detector.
 *
 * The plugin manager calls `genai_query_hook` with a flat
 * ProxySQL_PluginQueryHookPayload (user/ip/schema/query) just before
 * each backend dispatch.  This file converts that payload into a call
 * to `Anomaly_Detector::analyze`, increments the appropriate
 * Prometheus counters, and translates the AnomalyResult back into the
 * ABI's ALLOW / DENY response.
 *
 * Carve-out history: this logic used to live in core, in
 * `MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_detect_ai_anomaly`
 * (lib/MySQL_Session.cpp), incrementing
 * `thread->status_variables.stvar[st_var_ai_*]` and writing an ER 1313
 * packet directly.  Step 3 of the GenAI plugin carve-out moved the
 * implementation here; counters became Prometheus counters owned by
 * the plugin (`proxysql_genai_detected_anomalies`,
 * `proxysql_genai_blocked_queries`); the error-packet generation moved
 * back into core's hot path (where it belongs) via the DENY branch of
 * the plugin query-hook ABI.
 *
 * @see plugins/genai/include/genai_plugin.h
 * @see plugins/genai/include/Anomaly_Detector.h
 */

#include "genai_plugin.h"
#include "Anomaly_Detector.h"
#include "GenAI_Thread.h"

#include "prometheus/counter.h"

#include <string>

class GenAI_Threads_Handler;
extern GenAI_Threads_Handler* GloGATH;

ProxySQL_PluginQueryHookResult genai_query_hook(const ProxySQL_PluginQueryHookPayload& payload) {
	GenAIPluginContext& ctx = genai_context();
	std::shared_lock<GenAIRWLock> runtime_guard(ctx.runtime_dependencies_mutex);

	// Detector not yet up (init failed, or hook fired between stop and
	// final unload): always allow.  The lock-free
	// proxysql_has_configured_plugin_query_hook() gate in core's
	// MySQL_Session / PgSQL_Session can't see "started" -- it only
	// knows the hook is registered -- so this is the right place to
	// degrade.
	if (ctx.anomaly_detector == nullptr) {
		return {ProxySQL_PluginQueryHookAction::allow, std::string()};
	}

	if (!ctx.started || GloGATH == nullptr || !GloGATH->variables.genai_enabled ||
	    !GloGATH->variables.genai_anomaly_enabled) {
		return {ProxySQL_PluginQueryHookAction::allow, std::string()};
	}

	// payload.query_text is NOT NUL-terminated; build a std::string of
	// exactly query_len bytes.
	const std::string query(payload.query_text != nullptr ? payload.query_text : "",
	                        payload.query_len);
	const std::string user(payload.user != nullptr ? payload.user : "");
	const std::string ip(payload.client_ip != nullptr ? payload.client_ip : "");
	const std::string schema(payload.schema != nullptr ? payload.schema : "");

	const AnomalyResult r = ctx.anomaly_detector->analyze(query, user, ip, schema);

	if (r.is_anomaly && ctx.metric_detected_anomalies != nullptr) {
		ctx.metric_detected_anomalies->Increment();
	}

	if (!r.should_block) {
		return {ProxySQL_PluginQueryHookAction::allow, std::string()};
	}

	if (ctx.metric_blocked_queries != nullptr) {
		ctx.metric_blocked_queries->Increment();
	}

	// Pass the detector's explanation through to the client.  Core's
	// hot path wraps it in the protocol-appropriate error packet
	// (ER 1313/HY000 for MySQL, ERRCODE_INSUFFICIENT_PRIVILEGE for PgSQL).
	std::string msg = "AI Anomaly Detection: ";
	msg += r.explanation;
	return {ProxySQL_PluginQueryHookAction::deny, std::move(msg)};
}
