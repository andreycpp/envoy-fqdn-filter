#pragma once

#include "envoy/network/filter.h"
#include "source/common/common/logger.h"

#include "filters/common/firewall_config.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace SniFilter {

using FirewallConfig = Filters::Common::Firewall::FirewallConfig;
using FirewallConfigSharedPtr = Filters::Common::Firewall::FirewallConfigSharedPtr;

class SniFilter : public Network::ReadFilter, Logger::Loggable<Logger::Id::filter> {
public:
  SniFilter(FirewallConfigSharedPtr config) : config_(std::move(config)) {}

  // Network::ReadFilter
  Network::FilterStatus onData(Buffer::Instance&, bool) override {
    return Network::FilterStatus::Continue;
  }
  Network::FilterStatus onNewConnection() override;
  void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override {
    read_callbacks_ = &callbacks;
  }

private:
  const FirewallConfigSharedPtr config_;
  Network::ReadFilterCallbacks* read_callbacks_{};
};

} // namespace SniFilter
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
