# Must fail: copies a directory outside the allowed one into the store.
builtins.path { path = ../outside; name = "outside-copy"; }
