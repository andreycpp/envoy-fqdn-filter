#include "filters/sni_filter/config.h"
#include "filters/sni_filter/sni_filter.h"
#include "filters/common/firewall_config.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace SniFilter {

Network::FilterFactoryCb
SniFilterNetworkFilterConfigFactory::createFilterFactoryFromProtoTyped(
    const FirewallProto& proto_config, Server::Configuration::FactoryContext&) {

  auto filter_config = std::make_shared<FirewallConfig>(proto_config);

  return [filter_config](Network::FilterManager& filter_manager) -> void {
    filter_manager.addReadFilter(std::make_shared<SniFilter>(filter_config));
  };
}

/**
 * Static registration for the sni filter. @see RegisterFactory.
 */
REGISTER_FACTORY(SniFilterNetworkFilterConfigFactory,
                 Server::Configuration::NamedNetworkFilterConfigFactory);

} // namespace SniFilter
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
