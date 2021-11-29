#pragma once

#include "filters/common/firewall.pb.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace Filters {
namespace Common {
namespace Firewall {

using FirewallProto =
    envoy::extensions::filters::common::firewall::v3alpha::FirewallProto;
using Rule =
    envoy::extensions::filters::common::firewall::v3alpha::Rule;

inline std::string ToString(Rule::Action action) {
  if (action == Rule::DENY) {
      return "DENY";
  } else if (action == Rule::ALLOW) {
      return "ALLOW";
  }
  return "UNKNOWN";
}

class FirewallConfig {
public:
  FirewallConfig(const FirewallProto& proto_config);

  std::tuple<Rule::Action, std::string> match(absl::string_view host);

private:
  const FirewallProto config_;
  std::vector<int> sorted_config_;

  void buildSortedConfig();
};

using FirewallConfigSharedPtr = std::shared_ptr<FirewallConfig>;

} // namespace Firewall
} // namespace Common
} // namespace Filters
} // namespace Extensions
} // namespace Envoy
