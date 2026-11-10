# Dedicated gVisor lab VM (Phase 2)

## Security boundary

Use a dedicated, disposable Linux VM for ZEROFACTOR only. Never install this runner on a workstation, production host, or machine holding ATIBON credentials/data. The runner needs access to the Docker socket; membership in the Docker group is effectively host-root access. Treat every runner job as privileged host code.

**Important for this repository:** ZEROFACTOR is public. GitHub warns that self-hosted runners are generally unsafe for public repositories because workflow code can compromise the host. The workflow in this repository is therefore manual-only, restricted to the `main` ref, has read-only repository permissions, and pauses at a protected GitHub Environment. This reduces exposure but does not eliminate it. For stronger isolation, move the lab workflow to a private operations repository and dispatch only a reviewed, pinned ZEROFACTOR commit.

## 1. VM baseline

Recommended starting profile (adjust after measuring workload):

- Ubuntu Server 24.04 LTS, x86_64; ARM64 is also supported by gVisor.
- 4 vCPU, 8 GiB RAM, 40+ GiB disposable disk.
- Current security updates and Linux kernel 5.6 or newer.
- No inbound public ports. Restrict outbound traffic to GitHub Actions endpoints and approved package/image sources.
- No production credentials, SSH agent forwarding, cloud instance role, mounted host home, or shared Docker socket.
- Snapshot the clean VM before runner registration. Destroy/revert it after each validation session.

## 2. Install Docker Engine

Install Docker Engine from the official Docker apt repository for the selected Ubuntu release. Follow the official Engine installation guide rather than using an unpinned convenience script:
https://docs.docker.com/engine/install/ubuntu/

Enable and verify the daemon:

```bash
sudo systemctl enable --now docker
sudo docker version
sudo docker info
```

Do not expose the Docker API over TCP.

## 3. Install gVisor runsc

Use the official gVisor apt repository (preferred over downloading a moving binary manually):

```bash
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list >/dev/null
sudo apt-get update
sudo apt-get install -y runsc
```

Register/re-register the Docker runtime and restart Docker:

```bash
sudo runsc install
sudo systemctl restart docker
docker info --format '{{json .Runtimes}}'
runsc --version
```

The Docker runtime list must contain `runsc`. A successful `docker run --runtime=runsc ...` smoke test is required. Do not silently fall back to `runc`.

Official references:
- gVisor installation: https://gvisor.dev/docs/user_guide/install/
- Docker quick start: https://gvisor.dev/docs/user_guide/quick_start/docker/

## 4. Preload a reviewed test image

Build or obtain a minimal, reviewed test image from a trusted build pipeline. Pin the image by immutable digest in the lab inventory, record its image ID, and transfer it to the VM through the approved artifact channel. Do not pull images during a test job.

```bash
docker load --input zerofactor-test-image.tar
docker image inspect local/zerofactor-test-runner:locked
```

Set the repository Actions variable `ZEROFACTOR_TEST_IMAGE` to the exact local image reference. The workflow fails if the variable is empty or the image is absent. Do not put credentials in this variable.

## 5. Register a one-job GitHub runner

Prefer an ephemeral runner and a clean VM image for every job. Create a repository-scoped runner from **Settings → Actions → Runners → New self-hosted runner** and use the current commands/token displayed by GitHub. Configure labels `linux,gvisor` and ephemeral mode:

```bash
./config.sh --url https://github.com/Oligens/ZEROFACTOR --token <SHORT_LIVED_RUNNER_TOKEN> --labels linux,gvisor --ephemeral --unattended
./run.sh
```

The token is short-lived: do not commit it, paste it into workflow YAML, or save it in repository variables. Use a dedicated unprivileged runner account; note that Docker access grants effective root privileges. Destroy or revert the VM after the single job.

## 6. Protect the workflow before running it

In **Settings → Environments**, create `gvisor-lab-approval` and configure required reviewers. Restrict deployment branches to `main`. Do not add secrets to this environment. Keep the repository Actions token read-only.

The workflow is `workflow_dispatch` only and runs only when dispatched from `main`. It checks out `main`, runs the host smoke test, and uploads host metadata and logs even when the smoke test fails. Never change it to run on `pull_request`, `pull_request_target`, or arbitrary branch refs on this self-hosted runner.

## 7. Execute and retain evidence

1. Confirm the VM snapshot, runner labels, environment reviewers, and preloaded image.
2. Start the ephemeral runner.
3. In Actions, run **gVisor host validation (manual)** from `main`.
4. Approve the protected environment.
5. Download the `gvisor-host-validation-evidence` artifact.
6. Verify `SHA256SUMS`; retain the artifact with the VM image/kernel/runtime versions and the run URL.
7. Revert/destroy the VM and unregister any non-ephemeral runner.

The smoke test checks selected controls (runtime selection, read-only mounts/root, and absence of the Docker socket). It is not a sandbox-escape certification, side-channel assessment, or proof against all resource-exhaustion attacks. Commission independent testing before making production isolation claims.

## Completion criteria

Phase 2 host validation is complete only when a real ephemeral VM runner executes the workflow successfully, evidence is retained and hash-verified, and the VM is destroyed/reverted. A configured workflow or a passing unit test alone does not satisfy this gate.
