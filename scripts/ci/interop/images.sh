# OP-155 m.3 (q), T42: the counterpart containers of the CI jobs differential and interop-lab,
# pinned by digest (resolved through the registry API, each past the 7-day cooldown of F-2).
# They run on CI only and go into no image.
# shellcheck shell=bash disable=SC2034
DEBIAN="debian@sha256:4bcb9db66237237d03b55b969271728dd3d955eaaa254b9db8a3db94550b1885"     # 13.2-slim
COMPOSER="composer@sha256:b09bccd91a78fe8a9ab4b33d707b862e8fe54fec17782e32683ad2a69c46867d"  # 2.9.8
PYTHON="python@sha256:d98cc29d3266e535dd9da1099688d9cb3ca4753813571e071763d17725460962"      # 3.13.17-slim
NODE="node@sha256:a6155384446670e9719bdc4fd0ebe4d4b29fb32a8d6aa523da3547a6cfbcf22c"          # 24.22.0-trixie-slim
SAML2_LEGACY="4.20.3"   # simplesamlphp/saml2-legacy, the SAML library of SimpleSAMLphp 2.5
# scim2-tester and the exact versions of what it imports
SCIM2_PIP="scim2-tester==0.6.4 scim2-client==0.14.1 scim2-models==0.12.4 httpx2==2.16.0"
