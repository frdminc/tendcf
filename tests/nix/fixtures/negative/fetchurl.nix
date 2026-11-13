# Must fail: network fetch (builtins.fetchurl) with an empty allowed-uris.
builtins.fetchurl "https://example.com/index.html"
