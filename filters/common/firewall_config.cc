#include "filters/common/firewall_config.h"

#include "absl/strings/ascii.h"
#include "absl/strings/str_format.h"
#include <numeric> // std::iota

namespace Envoy {
namespace Extensions {
namespace Filters {
namespace Common {
namespace Firewall {

const auto ReasonEmptyHost = "empty host";
const auto ReasonDefaultAction = "default action";
const auto ReasonCustomerRule = "customer rule '%s' match '%s'";

// copied from source/extensions/tracers/xray/util.cc
bool wildcardMatch(absl::string_view pattern, absl::string_view input) {
  if (pattern.empty()) {
    return input.empty();
  }

  // Check the special case of a single * pattern, as it's common.
  constexpr char glob = '*';
  if (pattern.size() == 1 && pattern[0] == glob) {
    return true;
  }

  size_t i = 0, p = 0, i_star = input.size(), p_star = 0;
  while (i < input.size()) {
    if (p < pattern.size() && absl::ascii_tolower(input[i]) == absl::ascii_tolower(pattern[p])) {
      ++i;
      ++p;
    } else if (p < pattern.size() && '?' == pattern[p]) {
      ++i;
      ++p;
    } else if (p < pattern.size() && pattern[p] == glob) {
      i_star = i;
      p_star = p++;
    } else if (i_star != input.size()) {
      i = ++i_star;
      p = p_star + 1;
    } else {
      return false;
    }
  }

  while (p < pattern.size() && pattern[p] == glob) {
    ++p;
  }

  return p == pattern.size() && i == input.size();
}

FirewallConfig::FirewallConfig(
    const FirewallProto& proto_config)
    : config_(proto_config) {
      buildSortedConfig();
    }

std::tuple<Rule::Action, std::string> FirewallConfig::match(absl::string_view host) {
  if (host.empty()) {
    return {Rule::DENY, ReasonEmptyHost};
  }

  for (auto & i : sorted_config_) {
    auto& rule = config_.rules(i);

    for (auto& match: rule.matches()) {

      // match FQDN
      for (auto& fqdn : match.destination_fqdns()) {
        if (wildcardMatch(absl::string_view(fqdn), host)) {
          return {rule.action(), absl::StrFormat(ReasonCustomerRule, rule.name(), match.name())};
        }
      }

    }
  }

  return {Rule::DENY, ReasonDefaultAction};
}

void FirewallConfig::buildSortedConfig() {
  sorted_config_.resize(config_.rules_size());
  std::iota(sorted_config_.begin(), sorted_config_.end(), 0);

  auto pri = [this](int i) -> auto { return config_.rules(i).priority(); };
  std::sort(sorted_config_.begin(), sorted_config_.end(), [pri](auto i, auto j) -> bool {
    return pri(i) < pri(j);
  });
}

} // namespace Fault
} // namespace Common
} // namespace Filters
} // namespace Extensions
} // namespace Envoy
