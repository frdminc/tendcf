# Allowed, but empty: under restrict-eval builtins.getEnv returns "" (the
# runner's HOME is set, so a non-empty result would mean the environment leaks
# into a recipe). The runner also checks it is non-empty with restrict-eval off.
builtins.getEnv "HOME"
