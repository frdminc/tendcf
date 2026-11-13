# Must fail: import-from-derivation (evaluation needs a build to finish).
let
  d = derivation {
    name = "ifd-fixture";
    system = builtins.currentSystem;
    builder = "/bin/sh";
    args = [ "-c" "echo 1 > $out" ];
  };
in
import d
