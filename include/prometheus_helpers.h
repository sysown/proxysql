#ifndef __PROXYSQL_PROMETHEUS_HELPERS_H
#define __PROXYSQL_PROMETHEUS_HELPERS_H

#include <prometheus/counter.h>
#include <prometheus/gauge.h>
#include <prometheus/family.h>
#include <string>

#include "proxysql.h"

using prometheus::Counter;
using prometheus::Gauge;

#define ILLFORMED_PMAP_MSG "Array element remains empty after initialization, map must be ill-formed."

/**
 * @brief Initalizes an array of 'prometheus::Counter*' with the data supplied in a map.
 *
 * @tparam map_idx_enum The enum holding the types of elements contained in the 'metrics_map' argument.
 *  This enum must contain an element '::counters'.
 * @tparam counters_enum The counters enum, holding all the identifiers of the metrics
 *  to be initialized in the 'counter_array' argument. It must contains a '::__size' element.
 * @tparam metrics_map The type of the metrics map, it should be a 'tuple' holding the following elements:
 *  {
 *     int: metric_identifier,
 *     std::string: metric_name,
 *     std::string: metric_help,
 *     std::map<string, string> metric_tags
 *  }
 * @param map The metrics map to be initialized.
 * @param counter_array The array of 'prometheus::Counter*' to be initialized.
 */
template <typename map_idx_enum, typename counters_enum, typename metrics_map>
void init_prometheus_counter_array(
	const metrics_map& map,
	std::array<prometheus::Counter*, counters_enum::__size>& counter_array
) {
	for (const auto& metric : std::get<map_idx_enum::counters>(map)) {
		const auto& tg_metric = std::get<0>(metric);
		const auto& metric_name = std::get<1>(metric);
		const auto& metric_help = std::get<2>(metric);
		const auto& metric_tags = std::get<3>(metric);
		prometheus::Family<prometheus::Counter>* metric_family = nullptr;

		if (metric_help.empty()) {
			metric_family =
				std::addressof(
					prometheus::BuildCounter()
					.Name(metric_name)
					.Register(*GloVars.prometheus_registry)
				);
		} else {
			metric_family =
				std::addressof(
					prometheus::BuildCounter()
					.Name(metric_name)
					.Help(metric_help)
					.Register(*GloVars.prometheus_registry)
				);
		}

		counter_array[tg_metric] =
			std::addressof(metric_family->Add(metric_tags));
	}

	for (const auto& array_elem : counter_array) {
		if (array_elem == nullptr) {
			proxy_error("init_prometheus_counter_array: " ILLFORMED_PMAP_MSG);
			assert(0);
		}
	}
}

/**
 * @brief Initalizes an array of 'prometheus::Gauge*' with the data supplied in a map.
 *
 * @tparam map_idx_enum The enum holding the types of elements contained in the 'metrics_map' argument.
 *  This enum must contain an element '::gauges'.
 * @tparam gauges_enum The counters enum, holding all the identifiers of the metrics
 *  to be initialized in the 'gauge_array' argument. It must contains a '::__size' element.
 * @tparam metrics_map The type of the metrics map, it should be a 'tuple' holding the following elements:
 *  {
 *     int: metric_identifier,
 *     std::string: metric_name,
 *     std::string: metric_help,
 *     std::map<string, string> metric_tags
 *  }
 * @param map The metrics map to be initialized.
 * @param gauge_array The array of 'prometheus::Gauge*' to be initialized.
 */
template <typename map_idx_enum, typename gauges_enum, typename metrics_map>
void init_prometheus_gauge_array(
	const metrics_map& map,
	std::array<prometheus::Gauge*, gauges_enum::__size>& gauge_array
) {
	for (const auto& metric : std::get<map_idx_enum::gauges>(map)) {
		const auto& tg_metric = std::get<0>(metric);
		const auto& metric_name = std::get<1>(metric);
		const auto& metric_help = std::get<2>(metric);
		const auto& metric_tags = std::get<3>(metric);
		prometheus::Family<prometheus::Gauge>* metric_family = nullptr;

		if (metric_help.empty()) {
			metric_family =
				std::addressof(
					prometheus::BuildGauge()
					.Name(metric_name)
					.Register(*GloVars.prometheus_registry)
				);
		} else {
			metric_family =
				std::addressof(
					prometheus::BuildGauge()
					.Name(metric_name)
					.Help(metric_help)
					.Register(*GloVars.prometheus_registry)
				);
		}

		gauge_array[tg_metric] =
			std::addressof(metric_family->Add(metric_tags));
	}

	for (const auto& array_elem : gauge_array) {
		if (array_elem == nullptr) {
			proxy_error("init_prometheus_gauge_array: " ILLFORMED_PMAP_MSG);
			assert(0);
		}
	}
}

/**
 * @brief Initalizes an array of 'prometheus::Family<prometheus::Counter>*' with the data supplied in a map.
 *
 * @tparam map_idx_enum The enum holding the types of elements contained in the 'metrics_map' argument.
 *  This enum must contain an element '::dyn_counters'.
 * @tparam dyn_counter_enum The counters enum, holding all the identifiers of the metrics
 *  to be initialized in the 'dyn_counter_array' argument. It must contains a '::__size' element.
 * @tparam metrics_map The type of the metrics map, it should be a 'tuple' holding the following elements:
 *  {
 *     int: metric_identifier,
 *     std::string: metric_name,
 *     std::string: metric_help,
 *     std::map<string, string> metric_tags
 *  }
 * @param map The metrics map to be initialized.
 * @param dyn_counter_array The array of 'prometheus::Family<prometheus::Counter>*' to be initialized.
 */
template <typename map_idx_enum, typename dyn_counter_enum, typename metrics_map>
void init_prometheus_dyn_counter_array(
	const metrics_map& map,
	std::array<prometheus::Family<prometheus::Counter>*, dyn_counter_enum::__size>& dyn_counter_array
) {
	for (const auto& metric : std::get<map_idx_enum::dyn_counters>(map)) {
		const auto& tg_metric = std::get<0>(metric);
		const auto& metric_name = std::get<1>(metric);
		const auto& metric_help = std::get<2>(metric);
		prometheus::Family<prometheus::Counter>* metric_family = nullptr;

		if (metric_help.empty()) {
			metric_family =
				std::addressof(
					prometheus::BuildCounter()
					.Name(metric_name)
					.Register(*GloVars.prometheus_registry)
				);
		} else {
			metric_family =
				std::addressof(
					prometheus::BuildCounter()
					.Name(metric_name)
					.Help(metric_help)
					.Register(*GloVars.prometheus_registry)
				);
		}

		dyn_counter_array[tg_metric] = metric_family;
	}

	for (const auto& array_elem : dyn_counter_array) {
		if (array_elem == nullptr) {
			proxy_error("init_prometheus_dyn_counter_array: " ILLFORMED_PMAP_MSG);
			assert(0);
		}
	}
}

/**
 * @brief Initalizes an array of 'prometheus::Family<prometheus::Gauge>*' with the data supplied in a map.
 *
 * @tparam map_idx_enum The enum holding the types of elements contained in the 'metrics_map' argument.
 *  This enum must contain an element '::dyn_gauges'.
 * @tparam dyn_gauge_enum The 'dyn_gauges' enum, holding all the identifiers of the metrics
 *  to be initialized in the 'dyn_gauge_array' argument. It must contains a '::__size' element.
 * @tparam metrics_map The type of the metrics map, it should be a 'tuple' holding the following elements:
 *  {
 *     int: metric_identifier,
 *     std::string: metric_name,
 *     std::string: metric_help,
 *     std::map<string, string> metric_tags
 *  }
 * @param map The metrics map to be initialized.
 * @param dyn_gauge_array The array of 'prometheus::Family<prometheus::Gauge>*' to be initialized.
 */
template <typename map_idx_enum, typename gauges_enum, typename metrics_map>
void init_prometheus_dyn_gauge_array(
	const metrics_map& map,
	std::array<prometheus::Family<prometheus::Gauge>*, gauges_enum::__size>& dyn_gauge_array
) {
	for (const auto& metric : std::get<map_idx_enum::dyn_gauges>(map)) {
		const auto& tg_metric = std::get<0>(metric);
		const auto& metric_name = std::get<1>(metric);
		const auto& metric_help = std::get<2>(metric);
		prometheus::Family<prometheus::Gauge>* metric_family = nullptr;

		if (metric_help.empty()) {
			metric_family =
				std::addressof(
					prometheus::BuildGauge()
					.Name(metric_name)
					.Register(*GloVars.prometheus_registry)
				);
		} else {
			metric_family =
				std::addressof(
					prometheus::BuildGauge()
					.Name(metric_name)
					.Help(metric_help)
					.Register(*GloVars.prometheus_registry)
				);
		}

		dyn_gauge_array[tg_metric] = metric_family;
	}

	for (const auto& array_elem : dyn_gauge_array) {
		if (array_elem == nullptr) {
			proxy_error("init_prometheus_dyn_gauge_array: " ILLFORMED_PMAP_MSG);
			assert(0);
		}
	}
}

/**
 * @brief Inline helper function to avoid code duplication while updating prometheus counters.
 *
 * @param counter The counter to be updated.
 * @param new_val The new value to be set in the counter.
 */
inline void p_update_counter(prometheus::Counter* const counter, const double new_val) {
	const auto& actual_val = counter->Value();
	counter->Increment(new_val - actual_val);
}

/**
 * @brief Updates the supplied gauge map gauge corresponding with the supplied identifier.
 *  In case the identifier doesn't exist in the map, a new gauge is created used the supplied
 *  metric labels and 'gauge family'.
 *
 * @param gauge_map The gauge map to be updated.
 * @param gauge_family The 'gauge family' required to create a new gauge if not present.
 * @param m_id The target gauge identifier.
 * @param m_labels The labels for creating the new gauge if not present.
 * @param new_val The new value to be set in the gauge.
 */
inline void p_update_map_gauge(
	std::map<std::string, prometheus::Gauge*>& gauge_map,
	prometheus::Family<prometheus::Gauge>* const gauge_family,
	const std::string& m_id,
	const std::map<std::string, std::string>& m_labels,
	const double& new_val
) {

	const auto& id_val = gauge_map.find(m_id);
	if (id_val != gauge_map.end()) {
		id_val->second->Set(new_val);
	} else {
		prometheus::Gauge* new_counter = std::addressof(gauge_family->Add(m_labels));
		gauge_map.insert({m_id, new_counter});

		new_counter->Set(new_val);
	}
}

/**
 * @brief Updates the supplied counter map counter which correspond with the supplied identifier.
 *  In case the identifier doesn't exist in the map, a new counter is created used the supplied
 *  metric labels and 'counter family'.
 *
 * @param counter_map The counter map to be updated.
 * @param counter_family The 'counter family' required to create a new counter if not present.
 * @param m_id The target counter identifier.
 * @param m_labels The labels for creating a new counter if not present.
 * @param new_val The new value to be set in the counter.
 */
inline void p_update_map_counter(
	std::map<std::string, prometheus::Counter*>& counter_map,
	prometheus::Family<prometheus::Counter>* const counter_family,
	const std::string& m_id,
	const std::map<std::string, std::string>& m_labels,
	const double& new_val
) {
	const auto& id_val = counter_map.find(m_id);
	if (id_val != counter_map.end()) {
		p_update_counter(id_val->second, new_val);
	} else {
		prometheus::Counter* new_counter = std::addressof(counter_family->Add(m_labels));
		counter_map.insert({m_id, new_counter});

		p_update_counter(new_counter, new_val);
	}
}

/**
 * @brief Updates the supplied counter map counter incrementing the counter that correspond
 *  with the supplied identifier. In case of non existing, it creates a new one and increment it.
 *
 * @param counter_map The counter map to be updated.
 * @param counter_family The 'counter family' required to create a new counter if not present.
 * @param m_id The target counter identifier.
 * @param m_labels The labels for creating a new counter if not present.
 */
inline void p_inc_map_counter(
	std::map<std::string, prometheus::Counter*>& counter_map,
	prometheus::Family<prometheus::Counter>* const counter_family,
	const std::string& m_id,
	const std::map<std::string, std::string>& m_labels
) {
	const auto& id_val = counter_map.find(m_id);
	if (id_val != counter_map.end()) {
		id_val->second->Increment();
	} else {
		prometheus::Counter* new_counter = std::addressof(counter_family->Add(m_labels));
		counter_map.insert({m_id, new_counter});

		new_counter->Increment();
	}
}

#endif /* __PROXYSQL_PROMETHEUS_HELPERS_H */
