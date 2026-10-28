# podwatch-eBPF

A small runtime security sensor for Kubernetes, built with eBPF.

It watches the Linux kernel for what containers do (programs they start, secret files they open, network connections they make) and, step by step, links each event to the pod that caused it.

> **Status: work in progress.** The kernel sensor works today. Pod mapping, detection rules, and tests are being added. See the [roadmap](#roadmap).

This is a solo learning project. Attacks are simulated in my own lab only. No live malware is used.

---

## Why this exists

Most security tools check things before they run (image scanners, firewalls). Runtime security asks a different question: **what is happening inside my running containers right now, and is it normal?**

An attacker inside a pod must still ask the kernel for everything: start a shell, read a secret, call home. If you watch those requests, you see the attack. eBPF lets me watch them from inside the kernel with low overhead and without a kernel module.

---

## What works today

| Feature | Status |
|---|---|
| `exec` / `exit` probe: which programs start and stop | Done |
| `openat` probe with **in-kernel filter** (service account token folder and `/etc/shadow` only) | Done |
| `connect` probe: destination IPv4 address and port | Done |
| `cgroup_id` on every event (tells container events from host events) | Done |
| Ring buffer **drop counter** (reports how many events were lost) | Done and tested |
| cgroup ID to pod / namespace mapping | In progress |
| Process tree per container | Planned |
| YAML detection rules + rule engine | Planned |
| Trace record and replay | Planned |
| Attack scenarios (lab only) | Planned |
| Replay tests in GitHub Actions CI | Planned |
| Results (detection and false alarms) | Planned |
| Demo video | Planned |

### Example output

A pod reading its service account token, then `curl` calling out:

```
17:20:30 OPEN  cat    166505  15023   /var/run/secrets/kubernetes.io/serviceaccount/token cg=10025
06:53:27 CONN  curl   664902  219178  172.66.147.243:80 cg=6155
```

`cg=` is the cgroup ID. Events from a container have a different number than events from the host.

When the sensor stops, it prints how many events it lost:

```
Dropped events: 0
```

I tested the counter by shrinking the ring buffer to 4 KB and running a burst of short programs. It reported 304 dropped events, so the counter works.

---

## How it works

```
[Linux kernel]
   eBPF probes: exec/exit, openat (filtered), connect
        |
        |  ring buffer  (drop counter in a BPF map)
        v
[Userspace loader]
   prints events  ->  (next) enrich with pod / namespace
        |
        v
[Rule engine]  ->  alerts          (planned)
```

- **Probes** are written in C with libbpf (CO-RE), attached to syscall tracepoints.
- **Filtering happens in the kernel.** The `openat` probe checks the file name and discards anything that is not a sensitive path, so userspace is not flooded and the ring buffer does not fill up.
- **Drop counter:** if the ring buffer has no room, the probe adds 1 to a map. The loader prints the total on exit.

---

## Planned detection rules

Rules will be small YAML files, each mapped to a MITRE ATT&CK for Containers technique (IDs will be added when I verify them).

1. **Shell in container:** a shell started inside a container.
2. **Service account token read:** the token file read by something other than the pod's own app.
3. **New outbound connection:** a pod connects to an address it has never used before.
4. **Package manager at runtime** (extra)
5. **Sensitive file read** (extra)

Every rule will have recorded attack and benign traces. In CI, attack traces must alert and benign traces must not. I want to report false alarms first, because a detector with many false alarms is not usable.

---

## Roadmap

- [x] Lab check: BTF present, k3s running, test pod
- [x] `exec` and `exit` probes with cgroup ID
- [x] `openat` probe with in-kernel filter
- [x] `connect` probe (IPv4)
- [x] Ring buffer drop counter
- [ ] cgroup ID to container to pod / namespace / image (resolve once, cache)
- [ ] Per-container process tree (`nginx -> sh -> curl`)
- [ ] YAML rule format and rule engine
- [ ] Trace recorder and replayer
- [ ] Attack scenarios for each rule (lab only)
- [ ] GitHub Actions: run replay tests on every push
- [ ] Results table: detection and false alarms per scenario
- [ ] Overhead benchmark (agent off vs on: CPU and p99 latency)
- [ ] `ptrace` and `setuid` probes
- [ ] Demo video: attack, detection
- [ ] Full threat model and privilege model write-up

Later ideas, if the core is finished: anomaly scoring with ML as a second signal, automatic pod quarantine with a NetworkPolicy, and a Helm chart.

---

## Limitations (known, and honest)

- **The `openat` filter is a fixed list** of two paths, matched by prefix. It is a noise cutter, not a detector. A file that is not on the list is not seen.
- **Path tricks can get around it:** relative paths and symlinks can avoid a name match.
- **`connect` is IPv4 only.** IPv6 and unix sockets are skipped.
- **`connect` is logged when the program tries**, not when it succeeds.
- **The drop count for `openat` includes events that would have been filtered anyway**, because the space is reserved before the file name is checked.
- **Short-lived processes** can exit before they are mapped to a pod. These will be marked `unknown`.
- **cgroup IDs change** when a pod restarts or the machine reboots, so the mapping must always be looked up fresh.
- **One node, no enforcement:** it only observes.

---

## Privilege model

Loading eBPF programs needs elevated rights: root, or `CAP_BPF` and `CAP_PERFMON`. In my lab I run the loader with `sudo`. A security sensor with wide permissions is itself a risk, so a full privilege write-up (what it can see and do, and how to limit it) is on the roadmap.

---

## Build and run

Tested on a Kali Linux ARM64 VM (UTM on Apple Silicon), kernel 6.19, with k3s. Needs BTF (`/sys/kernel/btf/vmlinux`).

```bash
# 1. get libbpf-bootstrap
git clone --recurse-submodules https://github.com/libbpf/libbpf-bootstrap
cd libbpf-bootstrap/examples/c

# 2. copy this repo's three files over the originals
cp /path/to/podwatch-eBPF/bootstrap.bpf.c .
cp /path/to/podwatch-eBPF/bootstrap.c .
cp /path/to/podwatch-eBPF/bootstrap.h .

# 3. build and run
make
sudo ./bootstrap
```

To see only open events: `sudo stdbuf -oL ./bootstrap | grep OPEN`

---

## What I learned (so far)

- **Uninitialized ring buffer memory:** space from `bpf_ringbuf_reserve` is not cleared. Every probe must set every event label, or an old value can make one event type print as another.
- **Helper functions and `SEC`:** a `SEC(...)` line attaches to the function directly below it. Putting it above a helper made libbpf fail with `program 'starts_with' is static and not supported`.
- **Declare before use:** a helper must be defined above the probe that calls it.
- **Network byte order:** the port in a `sockaddr` is stored with its bytes flipped, so it needs `bpf_ntohs`.
- **Why filter in the kernel:** filtering in userspace would still let the kernel send every event first, so the noise and the lost events would already have happened.

---

## Safety

Lab only. Everything runs against workloads I deploy myself in my own local cluster. No live malware. Attacks are simulated behaviors (reading a token, spawning a shell, connecting to a local listener).

---

## Credits

Built on [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap). Design ideas from reading the docs of Falco and Tetragon (used as references, not deployed).

## License

See `LICENSE`.
