# Allowed: restrict-eval does not disable impure constants (pure-eval does,
# and is not used). Documents that a recipe can read the clock.
builtins.currentTime > 0
