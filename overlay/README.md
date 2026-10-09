# Upstream patch overlay

Patches on libntech and cfengine/core that tendcf's shipped policy depends
on, pinned to one upstream commit per component, applied by
[`bin/overlay.py`](../bin/overlay.py). Why it exists, what may go in it, and
how a patch leaves: [`docs/architecture/upstream-overlay.md`](../docs/architecture/upstream-overlay.md).
The issue is [frdminc/tendcf#3](https://github.com/frdminc/tendcf/issues/3).

| Path | What |
| --- | --- |
| `overlay.json` | the manifest: per component, the upstream, the fork, the pinned base, and each patch's provenance (register id, fork branch, upstream PR and its state, what shipped code it protects, when it retires) |
| `libntech/NNNN-*.patch` | `git format-patch` output, applied in order onto `libntech.base` |
| `core/NNNN-*.patch` | the same for cfengine/core, onto `core.base` |

```bash
bin/overlay.py status                                   # what is pinned
bin/overlay.py lint                                     # manifest and files agree (CI, every push)
bin/overlay.py self-test                                # the mechanism works (CI, every push)
bin/overlay.py check libntech --repo ~/src/libntech-overlay --against origin/master   # drift?
bin/overlay.py retired core --repo ~/src/cfengine-core --against upstream/master      # caught up?
bin/overlay.py apply core --checkout <clean checkout at core.base>                    # build input
```

Every file here is generated from a fork branch by `bin/overlay.py export`;
edit the fork, re-export, commit. Hand-editing a `.patch` loses the
provenance the `From` line carries, and `lint` will say so.
