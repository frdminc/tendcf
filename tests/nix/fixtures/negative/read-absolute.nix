# Must fail: reads a file outside the recipe directory by absolute path.
builtins.readFile /etc/passwd
