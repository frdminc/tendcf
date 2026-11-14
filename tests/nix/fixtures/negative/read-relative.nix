# Must fail: reads a file outside the recipe directory by relative path.
builtins.readFile ../outside/secret.txt
