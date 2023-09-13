#include "zeek/telemetry/Counter.h"

#include "opentelemetry/metrics/provider.h"

using namespace zeek::telemetry;

IntCounterFamily::IntCounterFamily(std::string_view prefix, std::string_view name,
                                   Span<const std::string_view> labels, std::string_view helptext,
                                   std::string_view unit, bool is_sum)
	: MetricFamily(prefix, name, labels, helptext, unit, is_sum)
	{
	auto p = opentelemetry::metrics::Provider::GetMeterProvider();
	auto m = p->GetMeter(std::string{prefix});
	instrument = m->CreateUInt64Counter(std::string{prefix} + "-" + std::string{name},
	                                    std::string{helptext}, std::string{unit});
	}

std::shared_ptr<IntCounter> IntCounterFamily::GetOrAdd(Span<const LabelView> labels)
	{
	return std::make_shared<IntCounter>(shared_from_this(), labels);
	}

IntCounter::IntCounter(std::shared_ptr<IntCounterFamily> family,
                       Span<const LabelView> labels) noexcept
	: family(std::move(family)), attributes(labels)
	{
	}

void IntCounter::Inc() noexcept
	{
	family->instrument->Add(1, attributes);
	value++;
	}

/**
 * Increments the value by @p amount.
 * @pre `amount >= 0`
 */
void IntCounter::Inc(uint64_t amount) noexcept
	{
	family->instrument->Add(amount, attributes);
	value += amount;
	}

/**
 * Increments the value by 1.
 * @return The new value.
 */
uint64_t IntCounter::operator++() noexcept
	{
	Inc();
	return value;
	}

DblCounterFamily::DblCounterFamily(std::string_view prefix, std::string_view name,
                                   Span<const std::string_view> labels, std::string_view helptext,
                                   std::string_view unit, bool is_sum)
	: MetricFamily(prefix, name, labels, helptext, unit, is_sum)
	{
	auto p = opentelemetry::metrics::Provider::GetMeterProvider();
	auto m = p->GetMeter(std::string{prefix});
	instrument = m->CreateDoubleCounter(std::string{prefix} + "-" + std::string{name},
	                                    std::string{helptext}, std::string{unit});
	}

std::shared_ptr<DblCounter> DblCounterFamily::GetOrAdd(Span<const LabelView> labels)
	{
	return std::make_shared<DblCounter>(shared_from_this(), labels);
	}

DblCounter::DblCounter(std::shared_ptr<DblCounterFamily> family,
                       Span<const LabelView> labels) noexcept
	: family(std::move(family)), attributes(labels)
	{
	}

void DblCounter::Inc() noexcept
	{
	family->instrument->Add(1, attributes);
	value++;
	}

/**
 * Increments the value by @p amount.
 * @pre `amount >= 0`
 */
void DblCounter::Inc(double amount) noexcept
	{
	family->instrument->Add(amount, attributes);
	value += amount;
	}
