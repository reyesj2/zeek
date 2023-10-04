// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/telemetry/Manager.h"

#include <algorithm>
#include <thread>
#include <variant>

#include "zeek/3rdparty/doctest.h"
#include "zeek/ID.h"
#include "zeek/telemetry/Collect.h"
#include "zeek/telemetry/Timer.h"
#include "zeek/telemetry/telemetry.bif.h"
#include "zeek/zeek-version.h"

#include "opentelemetry/exporters/memory/in_memory_metric_exporter_factory.h"
#include "opentelemetry/exporters/ostream/metric_exporter_factory.h"
#include "opentelemetry/exporters/prometheus/exporter_factory.h"
#include "opentelemetry/exporters/prometheus/exporter_options.h"
#include "opentelemetry/metrics/provider.h"
#include "opentelemetry/sdk/metrics/export/periodic_exporting_metric_reader_factory.h"
#include "opentelemetry/sdk/metrics/meter.h"
#include "opentelemetry/sdk/metrics/meter_provider.h"
#include "opentelemetry/sdk/metrics/meter_provider_factory.h"
#include "opentelemetry/sdk/metrics/push_metric_exporter.h"
#include "opentelemetry/sdk/metrics/view/instrument_selector_factory.h"
#include "opentelemetry/sdk/metrics/view/meter_selector_factory.h"
#include "opentelemetry/sdk/metrics/view/view_factory.h"

namespace metrics_sdk = opentelemetry::sdk::metrics;
namespace common = opentelemetry::common;
namespace exportermetrics = opentelemetry::exporter::metrics;
namespace metrics_api = opentelemetry::metrics;

namespace zeek::telemetry
	{

Manager::Manager()
	: metrics_name("zeek"), metrics_version(VERSION),
	  metrics_schema("https://opentelemetry.io/schemas/1.2.0")
	{
	auto meter_provider = metrics_sdk::MeterProviderFactory::Create();
	auto* p = static_cast<metrics_sdk::MeterProvider*>(meter_provider.release());
	std::shared_ptr<metrics_api::MeterProvider> provider_sp(p);
	metrics_api::Provider::SetMeterProvider(provider_sp);
	}

Manager::~Manager()
	{
	std::shared_ptr<opentelemetry::metrics::MeterProvider> none;
	metrics_api::Provider::SetMeterProvider(none);
	}

void Manager::InitPostScript()
	{
	auto mp = metrics_api::Provider::GetMeterProvider();
	auto* p = static_cast<metrics_sdk::MeterProvider*>(mp.get());

	if ( auto env = getenv("BROKER_METRICS_PORT") )
		{
		opentelemetry::exporter::metrics::PrometheusExporterOptions exporter_options;
		exporter_options.url = util::fmt("localhost:%s", env);
		auto exporter = exportermetrics::PrometheusExporterFactory::Create(exporter_options);
		p->AddMetricReader(std::move(exporter));
		}

	if ( auto env = getenv("OTEL_DEBUG") )
		{
		auto os_exporter = exportermetrics::OStreamMetricExporterFactory::Create();
		auto im_exporter = exportermetrics::InMemoryMetricExporterFactory::Create();

		metrics_sdk::PeriodicExportingMetricReaderOptions options;
		options.export_interval_millis = std::chrono::milliseconds(1000);
		options.export_timeout_millis = std::chrono::milliseconds(500);

		auto reader = metrics_sdk::PeriodicExportingMetricReaderFactory::Create(
			std::move(os_exporter), options);
		p->AddMetricReader(std::move(reader));
		}

	std::string counter_name = metrics_name + "_counter";
	auto instrument_selector = metrics_sdk::InstrumentSelectorFactory::Create(
		metrics_sdk::InstrumentType::kCounter, counter_name, "");
	auto meter_selector = metrics_sdk::MeterSelectorFactory::Create(metrics_name, metrics_version,
	                                                                metrics_schema);
	auto sum_view = metrics_sdk::ViewFactory::Create(metrics_name, "description", "",
	                                                 metrics_sdk::AggregationType::kSum);
	p->AddView(std::move(instrument_selector), std::move(meter_selector), std::move(sum_view));

	// histogram view
	std::string histogram_name = metrics_name + "_histogram";
	auto histogram_instrument_selector = metrics_sdk::InstrumentSelectorFactory::Create(
		metrics_sdk::InstrumentType::kHistogram, counter_name, "");
	auto histogram_meter_selector = metrics_sdk::MeterSelectorFactory::Create(
		histogram_name, metrics_version, metrics_schema);
	auto histogram_view = metrics_sdk::ViewFactory::Create(
		histogram_name, "description", "", metrics_sdk::AggregationType::kHistogram);
	p->AddView(std::move(histogram_instrument_selector), std::move(histogram_meter_selector),
	           std::move(histogram_view));
	}

std::shared_ptr<MetricFamily> Manager::LookupFamily(std::string_view prefix,
                                                    std::string_view name) const
	{
	auto check = [&](const auto& fam)
	{
		return fam->Prefix() == prefix && fam->Name() == name;
	};

	if ( auto it = std::find_if(families.begin(), families.end(), check); it != families.end() )
		return *it;

	return nullptr;
	}

// -- collect metric stuff -----------------------------------------------------

std::vector<CollectedValueMetric> Manager::CollectMetrics(std::string_view prefix,
                                                          std::string_view name)
	{
	std::vector<CollectedValueMetric> result;

	for ( const auto& family : families )
		{
		if ( family->Matches(prefix, name) )
			{
			auto metrics = family->CollectMetrics();
			std::move(metrics.begin(), metrics.end(), std::back_inserter(result));
			}
		}

	return result;
	}

std::vector<CollectedHistogramMetric> Manager::CollectHistogramMetrics(std::string_view prefix,
                                                                       std::string_view name)
	{
	std::vector<CollectedHistogramMetric> result;

	for ( const auto& family : families )
		{
		if ( family->Matches(prefix, name) )
			{
			auto metrics = family->CollectHistogramMetrics();
			std::move(metrics.begin(), metrics.end(), std::back_inserter(result));
			}
		}

	return result;
	}

	} // namespace zeek::telemetry

// -- unit tests ---------------------------------------------------------------

using namespace std::literals;
using namespace zeek::telemetry;

namespace
	{

template <class T> auto toVector(zeek::Span<T> xs)
	{
	std::vector<std::remove_const_t<T>> result;
	for ( auto&& x : xs )
		result.emplace_back(x);
	return result;
	}

	} // namespace

SCENARIO("telemetry managers provide access to counter families")
	{
	GIVEN("a telemetry manager")
		{
		Manager mgr;
		WHEN("retrieving an IntCounter family")
			{
			auto family = mgr.CounterFamily("zeek", "requests", {"method"}, "test", "1", true);
			THEN("the family object stores the parameters")
				{
				CHECK_EQ(family->Prefix(), "zeek"sv);
				CHECK_EQ(family->Name(), "requests"sv);
				CHECK_EQ(toVector(family->LabelNames()), std::vector{"method"s});
				CHECK_EQ(family->Helptext(), "test"sv);
				CHECK_EQ(family->Unit(), "1"sv);
				CHECK_EQ(family->IsSum(), true);
				}
			AND_THEN("GetOrAdd returns the same metric for the same labels")
				{
				auto first = family->GetOrAdd({{"method", "get"}});
				auto second = family->GetOrAdd({{"method", "get"}});
				CHECK_EQ(first, second);
				}
			AND_THEN("GetOrAdd returns different metric for the disjoint labels")
				{
				auto first = family->GetOrAdd({{"method", "get"}});
				auto second = family->GetOrAdd({{"method", "put"}});
				CHECK_NE(first, second);
				}
			}
		WHEN("retrieving a DblCounter family")
			{
			auto family = mgr.CounterFamily<double>("zeek", "runtime", {"query"}, "test", "seconds",
			                                        true);
			THEN("the family object stores the parameters")
				{
				CHECK_EQ(family->Prefix(), "zeek"sv);
				CHECK_EQ(family->Name(), "runtime"sv);
				CHECK_EQ(toVector(family->LabelNames()), std::vector{"query"s});
				CHECK_EQ(family->Helptext(), "test"sv);
				CHECK_EQ(family->Unit(), "seconds"sv);
				CHECK_EQ(family->IsSum(), true);
				}
			AND_THEN("GetOrAdd returns the same metric for the same labels")
				{
				auto first = family->GetOrAdd({{"query", "foo"}});
				auto second = family->GetOrAdd({{"query", "foo"}});
				CHECK_EQ(first, second);
				}
			AND_THEN("GetOrAdd returns different metric for the disjoint labels")
				{
				auto first = family->GetOrAdd({{"query", "foo"}});
				auto second = family->GetOrAdd({{"query", "bar"}});
				CHECK_NE(first, second);
				}
			}
		}
	}

SCENARIO("telemetry managers provide access to gauge families")
	{
	GIVEN("a telemetry manager")
		{
		Manager mgr;
		WHEN("retrieving an IntGauge family")
			{
			auto family = mgr.GaugeFamily("zeek", "open-connections", {"protocol"}, "test");
			THEN("the family object stores the parameters")
				{
				CHECK_EQ(family->Prefix(), "zeek"sv);
				CHECK_EQ(family->Name(), "open-connections"sv);
				CHECK_EQ(toVector(family->LabelNames()), std::vector{"protocol"s});
				CHECK_EQ(family->Helptext(), "test"sv);
				CHECK_EQ(family->Unit(), "1"sv);
				CHECK_EQ(family->IsSum(), false);
				}
			AND_THEN("GetOrAdd returns the same metric for the same labels")
				{
				auto first = family->GetOrAdd({{"protocol", "tcp"}});
				auto second = family->GetOrAdd({{"protocol", "tcp"}});
				CHECK_EQ(first, second);
				}
			AND_THEN("GetOrAdd returns different metric for the disjoint labels")
				{
				auto first = family->GetOrAdd({{"protocol", "tcp"}});
				auto second = family->GetOrAdd({{"protocol", "quic"}});
				CHECK_NE(first, second);
				}
			}
		WHEN("retrieving a DblGauge family")
			{
			auto family = mgr.GaugeFamily<double>("zeek", "water-level", {"river"}, "test",
			                                      "meters");
			THEN("the family object stores the parameters")
				{
				CHECK_EQ(family->Prefix(), "zeek"sv);
				CHECK_EQ(family->Name(), "water-level"sv);
				CHECK_EQ(toVector(family->LabelNames()), std::vector{"river"s});
				CHECK_EQ(family->Helptext(), "test"sv);
				CHECK_EQ(family->Unit(), "meters"sv);
				CHECK_EQ(family->IsSum(), false);
				}
			AND_THEN("GetOrAdd returns the same metric for the same labels")
				{
				auto first = family->GetOrAdd({{"river", "Sacramento"}});
				auto second = family->GetOrAdd({{"river", "Sacramento"}});
				CHECK_EQ(first, second);
				}
			AND_THEN("GetOrAdd returns different metric for the disjoint labels")
				{
				auto first = family->GetOrAdd({{"query", "Sacramento"}});
				auto second = family->GetOrAdd({{"query", "San Joaquin"}});
				CHECK_NE(first, second);
				}
			}
		}
	}

SCENARIO("telemetry managers provide access to histogram families")
	{
	GIVEN("a telemetry manager")
		{
		Manager mgr;
		WHEN("retrieving an IntHistogram family")
			{
			int64_t buckets[] = {10, 20};
			auto family = mgr.HistogramFamily("zeek", "payload-size", {"protocol"}, buckets, "test",
			                                  "bytes");
			THEN("the family object stores the parameters")
				{
				CHECK_EQ(family->Prefix(), "zeek"sv);
				CHECK_EQ(family->Name(), "payload-size"sv);
				CHECK_EQ(toVector(family->LabelNames()), std::vector{"protocol"s});
				CHECK_EQ(family->Helptext(), "test"sv);
				CHECK_EQ(family->Unit(), "bytes"sv);
				CHECK_EQ(family->IsSum(), false);
				}
			AND_THEN("GetOrAdd returns the same metric for the same labels")
				{
				auto first = family->GetOrAdd({{"protocol", "tcp"}});
				auto second = family->GetOrAdd({{"protocol", "tcp"}});
				CHECK_EQ(first, second);
				}
			AND_THEN("GetOrAdd returns different metric for the disjoint labels")
				{
				auto first = family->GetOrAdd({{"protocol", "tcp"}});
				auto second = family->GetOrAdd({{"protocol", "udp"}});
				CHECK_NE(first, second);
				}
			}
		WHEN("retrieving a DblHistogram family")
			{
			double buckets[] = {10.0, 20.0};
			auto family = mgr.HistogramFamily<double>("zeek", "parse-time", {"protocol"}, buckets,
			                                          "test", "seconds");
			THEN("the family object stores the parameters")
				{
				CHECK_EQ(family->Prefix(), "zeek"sv);
				CHECK_EQ(family->Name(), "parse-time"sv);
				CHECK_EQ(toVector(family->LabelNames()), std::vector{"protocol"s});
				CHECK_EQ(family->Helptext(), "test"sv);
				CHECK_EQ(family->Unit(), "seconds"sv);
				CHECK_EQ(family->IsSum(), false);
				}
			AND_THEN("GetOrAdd returns the same metric for the same labels")
				{
				auto first = family->GetOrAdd({{"protocol", "tcp"}});
				auto second = family->GetOrAdd({{"protocol", "tcp"}});
				CHECK_EQ(first, second);
				}
			AND_THEN("GetOrAdd returns different metric for the disjoint labels")
				{
				auto first = family->GetOrAdd({{"protocol", "tcp"}});
				auto second = family->GetOrAdd({{"protocol", "udp"}});
				CHECK_NE(first, second);
				}
			AND_THEN("Timers add observations to histograms")
				{
				auto hg = family->GetOrAdd({{"protocol", "tst"}});
				CHECK_EQ(hg->Sum(), 0.0);
					{
					Timer observer{hg};
					std::this_thread::sleep_for(1ms);
					}
				CHECK_NE(hg->Sum(), 0.0);
				}
			}
		}
	}
