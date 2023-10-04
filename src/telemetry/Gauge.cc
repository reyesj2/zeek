#include "zeek/telemetry/Gauge.h"

#include "opentelemetry/metrics/provider.h"

using namespace zeek::telemetry;

IntGaugeFamily::IntGaugeFamily(std::string_view prefix, std::string_view name,
                               Span<const std::string_view> labels, std::string_view helptext,
                               std::string_view unit, bool is_sum)
	: MetricFamily(prefix, name, labels, helptext, unit, is_sum)
	{
	auto p = opentelemetry::metrics::Provider::GetMeterProvider();
	auto m = p->GetMeter(std::string{prefix});
	instrument = m->CreateInt64UpDownCounter(std::string{prefix} + "-" + std::string{name},
	                                         std::string{helptext}, std::string{unit});
	}

std::shared_ptr<IntGauge> IntGaugeFamily::GetOrAdd(Span<const LabelView> labels)
	{
	auto check = [&](const std::shared_ptr<IntGauge>& gauge)
	{
		return gauge->CompareLabels(labels);
	};

	if ( auto it = std::find_if(gauges.begin(), gauges.end(), check); it != gauges.end() )
		return *it;

	auto gauge = std::make_shared<IntGauge>(shared_from_this(), labels);
	gauges.push_back(gauge);
	return gauge;
	}

/**
 * @return All gauge and gauge metrics and their values matching prefix and name.
 * @param prefix The prefix pattern to use for filtering. Supports globbing.
 * @param name The name pattern to use for filtering. Supports globbing.
 */
std::vector<CollectedValueMetric> IntGaugeFamily::CollectMetrics() const
	{
	std::vector<CollectedValueMetric> result;
	result.reserve(gauges.size());

	for ( const auto& cntr : gauges )
		result.emplace_back(BifEnum::Telemetry::MetricType::INT_GAUGE, shared_from_this(),
		                    cntr->Labels(), cntr->Value());

	return result;
	}

DblGaugeFamily::DblGaugeFamily(std::string_view prefix, std::string_view name,
                               Span<const std::string_view> labels, std::string_view helptext,
                               std::string_view unit, bool is_sum)
	: MetricFamily(prefix, name, labels, helptext, unit, is_sum)
	{
	auto p = opentelemetry::metrics::Provider::GetMeterProvider();
	auto m = p->GetMeter(std::string{prefix});
	instrument = m->CreateDoubleUpDownCounter(std::string{prefix} + "-" + std::string{name},
	                                          std::string{helptext}, std::string{unit});
	}

std::shared_ptr<DblGauge> DblGaugeFamily::GetOrAdd(Span<const LabelView> labels)
	{
	auto check = [&](const std::shared_ptr<DblGauge>& gauge)
	{
		return gauge->CompareLabels(labels);
	};

	if ( auto it = std::find_if(gauges.begin(), gauges.end(), check); it != gauges.end() )
		return *it;

	auto gauge = std::make_shared<DblGauge>(shared_from_this(), labels);
	gauges.push_back(gauge);
	return gauge;
	}

/**
 * @return All counter and gauge metrics and their values matching prefix and name.
 * @param prefix The prefix pattern to use for filtering. Supports globbing.
 * @param name The name pattern to use for filtering. Supports globbing.
 */
std::vector<CollectedValueMetric> DblGaugeFamily::CollectMetrics() const
	{
	std::vector<CollectedValueMetric> result;
	result.reserve(gauges.size());

	for ( const auto& cntr : gauges )
		result.emplace_back(BifEnum::Telemetry::MetricType::DOUBLE_GAUGE, shared_from_this(),
		                    cntr->Labels(), cntr->Value());

	return result;
	}
