#!/bin/sh
# SSH_ASKPASS helper for the one password login in `golden` (the vanilla image's
# published admin credential). ssh runs this with the prompt as $1 and reads the
# answer from stdout. The value arrives through the environment of the one ssh
# process, never on a command line, and is never logged. Everything after
# `golden` uses key login.
printf '%s\n' "${TENDCF_VM_BOOTSTRAP_PW:?}"
