# Positive fixture: a recipe that reads a sibling file and imports a sibling
# expression, and must evaluate to JSON under the documented limits.
{
  site = "ok";
  greeting = builtins.readFile ./data.txt;
  helper = import ./helper.nix;
}
