#ifndef __PROXYSQL_PROMETHEUS_HELPERS_H
#define __PROXYSQL_PROMETHEUS_HELPERS_H

#include <prometheus/counter.h>
#include <prometheus/gauge.h>

#include "prometheus/family.h"
#include "proxysql.h"

using prometheus::Counter;
using prometheus::Gauge;

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
}

#endif /* __PROXYSQL_PROMETHEUS_HELPERS_H */