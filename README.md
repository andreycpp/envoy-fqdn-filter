# Envoy filters for FQDN filtering on TLS SNI and HTTP Host header

## Prerequisites

See general instructions [here](https://github.com/envoyproxy/envoy/blob/main/bazel/README.md)

Ubuntu 18.04:
```
# bazel
sudo wget -O /usr/local/bin/bazel https://github.com/bazelbuild/bazelisk/releases/latest/download/bazelisk-linux-$([ $(uname -m) = "aarch64" ] && echo "arm64" || echo "amd64")
sudo chmod +x /usr/local/bin/bazel

# prerequisites
sudo apt install cmake ninja-build

# clang-10
sudo apt install clang-10 lld-10
sudo ln -sf /usr/bin/llvm-config-10 /usr/bin/llvm-config
envoy/bazel/setup_clang.sh /usr
echo "build --config=clang" >> user.bazelrc

# C++17 headers e.g. <filesystem>
sudo apt install g++-8
```

## Building

To build the Envoy static binary:

1. `git submodule update --init`
2. `bazel build //filters:envoy`

## Testing

To manually test the `url_filter` run the following commands:
1. `cd examples/`
2. `./sni_http_filter_example.sh`
3. `sudo -u envoy ../bazel-bin/filters/envoy -c sni_http_filter_example.yaml`

Then in another terminal session, use `curl` to verify that FQDNs are being
blocked/allowed as per the example configuration (eg. `curl http://www.microsoft.com`
should be blocked).

To run the regular Envoy tests from this project:

`bazel test @envoy//test/...`

## How it works

The [Envoy repository](https://github.com/envoyproxy/envoy/) is provided as a submodule.
The [`WORKSPACE`](WORKSPACE) file maps the `@envoy` repository to this local path.

The [`BUILD`](filters/BUILD) file introduces a new Envoy static binary target, `envoy`,
that links together the new filters and `@envoy//source/exe:envoy_main_entry_lib`. The
filters register themselves during the static initialization phase of the
Envoy binary as new filters.
