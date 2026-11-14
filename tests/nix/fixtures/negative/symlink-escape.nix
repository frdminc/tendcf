# Must fail: ./escape-link is a symlink inside the allowed directory that
# resolves to ../outside/secret.txt, outside it.
builtins.readFile ./escape-link
