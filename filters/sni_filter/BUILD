load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

package(default_visibility = ["//visibility:public"])

envoy_cc_library(
    name = "sni_filter_lib",
    srcs = ["sni_filter.cc"],
    hdrs = ["sni_filter.h"],
    repository = "@envoy",
    deps = [
        "@envoy//envoy/network:connection_interface",
        "@envoy//envoy/network:filter_interface",
        "//filters/common:firewall_config_lib",
    ],
)

envoy_cc_library(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    repository = "@envoy",
    deps = [
        "@envoy//envoy/registry",
        "@envoy//envoy/server:filter_config_interface",
        "@envoy//source/extensions/filters/network/common:factory_base_lib",
        ":sni_filter_lib",
    ],
)
