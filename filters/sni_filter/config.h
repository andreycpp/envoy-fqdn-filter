#pragma once

#include "filters/common/firewall.pb.h"
#include "filters/common/firewall.pb.validate.h"

#include "source/extensions/filters/network/common/factory_base.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace SniFilter {

using FirewallProto =
    envoy::extensions::filters::common::firewall::v3alpha::FirewallProto;

/**
 * Config registration for the sni filter. @see
 * NamedNetworkFilterConfigFactory.
 */
class SniFilterNetworkFilterConfigFactory : public Common::FactoryBase<FirewallProto> {
public:
  SniFilterNetworkFilterConfigFactory() : FactoryBase("envoy.filters.network.sni_filter") {}

private:
  Network::FilterFactoryCb
  createFilterFactoryFromProtoTyped(const FirewallProto& proto_config,
                                    Server::Configuration::FactoryContext& context) override;
};

} // namespace SniFilter
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
