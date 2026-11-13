# Must fail: network fetch (builtins.fetchTarball) with an empty allowed-uris.
builtins.fetchTarball "https://example.com/a.tar.gz"
