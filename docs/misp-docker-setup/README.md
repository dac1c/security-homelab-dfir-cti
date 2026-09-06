# MISP Setup via Docker (Laptop / CTI Environment)

## Overview

This documents standing up **MISP (Malware Information Sharing Platform)** as
the first component of the CTI (Cyber Threat Intelligence) side of the lab,
running via Docker on the laptop (separate from the desktop, which hosts the
DFIR/SOC environment: pfSense, Windows/Linux targets, and Wazuh).

MISP is used here to demonstrate turning a DFIR finding into a structured,
shareable threat intelligence record — the first MISP event created in this
lab is a direct structured representation of
[`dfir-writeups/02-ssh-bruteforce-linux-victim.md`](../../dfir-writeups/02-ssh-bruteforce-linux-victim.md).

---

## Environment

* **Host:** Laptop (Windows 11, Intel i5-12th gen, 16GB RAM)
* **Container runtime:** Docker Desktop, using the WSL2 backend
* **Linux layer:** Ubuntu (via WSL2)
* **MISP deployment:** Official [`misp-docker`](https://github.com/MISP/misp-docker) Compose stack (core, database, redis, modules, mail)

---

## Setup Steps

### 1. WSL2 + Docker Desktop

Installed WSL2 (`wsl --install`) and Docker Desktop, with WSL2 integration
enabled for the Ubuntu distribution (Settings → Resources → WSL Integration).
Docker containers for Linux workloads run through this WSL2 layer rather than
a dedicated VM, which is lighter on RAM than adding another full VirtualBox
guest — an important constraint given the laptop's 16GB total memory.

### 2. Clone the official MISP Docker repo

```bash
git clone https://github.com/MISP/misp-docker.git
cd misp-docker
```

Using the officially maintained Compose template rather than writing one from
scratch — standard practice for well-supported open-source infrastructure.

### 3. Configure `.env`

Copied `template.env` to `.env` and set the minimum required variables:

```
ADMIN_EMAIL=admin@homelab.local
ADMIN_ORG=HomelabSOC
ADMIN_PASSWORD=<set, stored in password manager>
BASE_URL=https://localhost
GPG_PASSPHRASE=<set, stored in password manager>
```

Everything else (MySQL credentials, Redis, LDAP/OIDC/AAD auth, S3 storage,
etc.) was left at default — none of it applies to a single-user local lab.

### 4. Bring up the stack

```bash
docker compose up -d
docker compose ps
```

All five containers (`misp-core`, `misp-db`, `misp-redis`, `misp-modules`,
`misp-mail`) came up healthy. MISP was then reachable at `https://localhost`
(self-signed certificate, expected browser warning).

---

## Troubleshooting: Docker Desktop WSL Integration Failure (coreutils conflict)

This was the most significant issue encountered, and worth documenting in
detail because the root cause was unusual and not something standard Docker
troubleshooting guides cover.

### Symptom

After enabling a `.wslconfig` memory limit (to cap WSL2's RAM usage, see
below), Docker Desktop began failing to integrate with the Ubuntu WSL
distribution, repeatedly showing:

```
WSL integration with distro 'Ubuntu' unexpectedly stopped. Do you want to restart it?
```

with an underlying error:

```
DockerDesktop/Wsl/ExecError: ... install -m 0755 ... : exit status 1
(stderr: install: No such file or directory)
```

### Diagnostic process

1. Removing the `.wslconfig` file entirely did **not** resolve the issue,
   ruling out the memory/processor limits as the cause.
2. WSL2 itself was confirmed healthy — Ubuntu could be started manually
   (`wsl -d Ubuntu`) and used normally outside of Docker Desktop.
3. The error pointed at a failure of the `install` command specifically, so
   the next step was checking that command directly:
   ```bash
   which install
   ls -la /usr/bin/install
   /usr/bin/install --version
   ```
4. This revealed `/usr/bin/install` was a symlink into
   `../lib/cargo/bin/coreutils/install`, and `--version` reported
   **`install (uutils coreutils) 0.8.0`** — not the standard GNU coreutils
   that Docker Desktop's internal WSL integration script expects.
5. `dpkg -S /usr/bin/install` confirmed the owning package was literally named
   `coreutils-from-uutils` — a Rust-based reimplementation of the standard
   Unix toolset, installed in place of GNU coreutils on this particular
   Ubuntu build. Docker Desktop's proxy-installation script relies on
   GNU-compatible `install` behavior and failed against the alternative
   implementation, even though the binary technically existed and ran.

### Root cause

The Ubuntu distribution had `coreutils-from-uutils` installed instead of
`coreutils-from-gnu`. Both packages are marked `essential`/`protected` at the
package-manager level and directly conflict with each other, which meant the
usual `apt remove` / `apt install --reinstall coreutils` approaches failed
outright — `apt` refused to remove an essential package, and refused to
install the GNU replacement while the conflicting uutils package was present,
producing an unresolvable dependency deadlock through ordinary means.

### Resolution

The conflict was broken by installing the GNU package directly via `dpkg`,
forcing past the conflict marker, which let `dpkg`'s own diversion mechanism
(`coreutils-switch`) cleanly swap every affected binary in one pass:

```bash
apt-get download coreutils-from-gnu
sudo dpkg -i --force-conflicts coreutils-from-gnu_*.deb
sudo apt install -f
```

This single command triggered `dpkg` to recognize that installing
`coreutils-from-gnu` should replace `coreutils-from-uutils` (satisfying the
underlying `coreutils` package's requirement that *one* of the two variants
be present at all times), and cleanly diverted all ~120 affected binaries
(`ls`, `cp`, `install`, `mv`, etc.) back to their GNU implementations.

Verification:
```bash
/usr/bin/install --version
# install (GNU coreutils) 9.7
```

After this, Docker Desktop's WSL integration restarted successfully with no
further errors, and the MISP containers — which had continued running inside
WSL2 the entire time, unaffected by the Docker Desktop GUI-level integration
failure — were confirmed healthy via `docker compose ps`.

### Lesson

A tool failing with a generic-looking error ("No such file or directory") is
not always missing a file — it can be running against an **incompatible
alternative implementation** of a command it assumes is the standard one.
When a script written against GNU tooling hits a non-GNU reimplementation
(uutils, busybox, etc.), the failure mode is often confusing because the
command exists, is executable, and even runs — it just doesn't behave
identically enough for scripts that depend on exact GNU semantics. Checking
`--version` output early, not just "does the binary exist," would have
identified this faster.

Also notable: two package-manager-protected packages providing conflicting
implementations of the same "virtual" role (here, `coreutils-from`) cannot
always be swapped with ordinary `apt remove`/`install` — sometimes `dpkg`
needs to be invoked directly with explicit force flags to let its diversion
mechanism handle the swap atomically.

---

## RAM Management Note

WSL2 has no default memory ceiling and will consume RAM opportunistically
(observed ~7.2GB for `VmmemWSL` under light load). A `.wslconfig` file was
used to cap this:

```
[wsl2]
memory=10GB
```

This is worth revisiting before starting the OpenCTI phase, since OpenCTI's
stack (Elasticsearch/OpenSearch, RabbitMQ, Redis, MinIO, workers) has a
heavier baseline memory requirement than MISP, and the laptop's 16GB total
is a hard constraint. MISP and OpenCTI are intended to run **sequentially**,
not simultaneously, for this reason — see the CTI phase notes for the planned
integration approach (MISP as an IoC feed source, imported into OpenCTI later).

---

## Outcome

* MISP is running and reachable at `https://localhost`.
* First event created: **"SSH Brute-Force Attack - Linux-Victim-01 (Purple Team Exercise)"**, containing 6 attributes (source IP, target port, targeted account, tool used, and MITRE ATT&CK context) and two MITRE ATT&CK Galaxy clusters (T1110 Brute Force, T1078 Valid Accounts), published within the local organisation.
* This demonstrates the full pipeline from raw DFIR finding → structured, shareable threat intelligence record.
