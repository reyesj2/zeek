#include "zeek/telemetry/Histogram.h"

#include "opentelemetry/metrics/provider.h"

using namespace zeek::telemetry;

IntHistogramFamily::IntHistogramFamily(std::string_view prefix, std::string_view name,
                                       Span<const std::string_view> labels,
                                       std::string_view helptext, std::string_view unit,
                                       bool is_sum)
	: MetricFamily(prefix, name, labels, helptext, unit, is_sum)
	{
	auto p = opentelemetry::metrics::Provider::GetMeterProvider();
	auto m = p->GetMeter(std::string{prefix});
	instrument = m->CreateUInt64Histogram(std::string{prefix} + "-" + std::string{name},
	                                      std::string{helptext}, std::string{unit});
	}

std::shared_ptr<IntHistogram> IntHistogramFamily::GetOrAdd(Span<const LabelView> labels)
	{
	auto check = [&](const std::shared_ptr<IntHistogram>& histogram)
	{
		return histogram->CompareLabels(labels);
	};

	if ( auto it = std::find_if(histograms.begin(), histograms.end(), check);
	     it != histograms.end() )
		return *it;

	auto histogram = std::make_shared<IntHistogram>(shared_from_this(), labels);
	histograms.push_back(histogram);
	return histogram;
	}

DblHistogramFamily::DblHistogramFamily(std::string_view prefix, std::string_view name,
                                       Span<const std::string_view> labels,
                                       std::string_view helptext, std::string_view unit,
                                       bool is_sum)
	: MetricFamily(prefix, name, labels, helptext, unit, is_sum)
	{
	auto p = opentelemetry::metrics::Provider::GetMeterProvider();
	auto m = p->GetMeter(std::string{prefix});
	instrument = m->CreateDoubleHistogram(std::string{prefix} + "-" + std::string{name},
	                                      std::string{helptext}, std::string{unit});
	}

std::shared_ptr<DblHistogram> DblHistogramFamily::GetOrAdd(Span<const LabelView> labels)
	{
	auto check = [&](const std::shared_ptr<DblHistogram>& histogram)
	{
		return histogram->CompareLabels(labels);
	};

	if ( auto it = std::find_if(histograms.begin(), histograms.end(), check);
	     it != histograms.end() )
		return *it;

	auto histogram = std::make_shared<DblHistogram>(shared_from_this(), labels);
	histograms.push_back(histogram);
	return histogram;
	}
