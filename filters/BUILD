load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
)
load("@envoy_api//bazel:api_build_system.bzl", "api_proto_package")

package(default_visibility = ["//visibility:public"])

envoy_cc_binary(
    name = "envoy",
    repository = "@envoy",
    deps = [
        "//filters/host_filter:config",
        "//filters/sni_filter:config",
        "@envoy//source/exe:envoy_main_entry_lib",
    ],
)
