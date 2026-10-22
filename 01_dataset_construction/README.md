# Dataset construction

Purpose: construct raw multi-source security-log runs from Docker scenarios.

Pre-generated raw logs and alignment indices: [Zenodo](https://doi.org/10.5281/zenodo.23536103).

<p align="center">
  <img src="../docs/figures/scenario_distribution.png" alt="Distribution of the 29 reproducible attack scenarios" width="55%">
</p>
<p align="center"><sub><i>The construction batch in <code>build.sh</code> covers 29 reproducible attack scenarios, grouped by application stack.</i></sub></p>

Scenario descriptions are in [scenario_descriptions.md](scenario_descriptions.md).

Primary entry points:

```bash
bash build.sh
BATCH=1 poetry run python main.py --config-path example/python-demo \
  --output-path results/python-demo
```

Runtime prerequisites:

- Linux with Bash, Docker Engine, and Docker Compose support;
- Python 3.11 and Poetry;
- Sysdig, tcpdump, conntrack, nsenter, and sudo/root capture privileges.

## Reproduce the build environment

Run these commands from this directory (the directory that contains
`build.sh`). They use only paths relative to the release tree.

Install the host packages and enable Docker:

```bash
sudo apt update
sudo apt install -y docker.io docker-compose gzip curl nano
sudo systemctl enable --now docker
```

Install Sysdig and the network-capture tools:

```bash
curl -s https://download.sysdig.com/stable/install-sysdig | sudo bash
sudo apt install -y tshark conntrack tcpdump
```

Install Python 3.11 if it is not already available, then install Poetry and
select that interpreter for the locked environment:

```bash
python3.11 --version
pip install --user poetry
poetry env use python3.11
poetry install
poetry run python main.py --help
```

Download the Docker image package (approximately 30.82 GB in total) from the
[SecLog Docker images record](https://doi.org/10.5281/zenodo.23474857).
Download all three parts:

- [`all_images.tar.gz.01`](https://zenodo.org/records/23474857/files/all_images.tar.gz.01?download=1)
- [`all_images.tar.gz.02`](https://zenodo.org/records/23474857/files/all_images.tar.gz.02?download=1)
- [`all_images.tar.gz.03`](https://zenodo.org/records/23474857/files/all_images.tar.gz.03?download=1)

Place all three parts beside `build.sh` in the current directory. Combine
them in numerical order, then import the reconstructed archive into Docker:

```bash
cat all_images.tar.gz.01 all_images.tar.gz.02 all_images.tar.gz.03 > all_images.tar.gz
sudo docker load --input ./all_images.tar.gz
```

Docker can load the gzip-compressed archive directly. All three parts are
required; see the README on the Zenodo record for additional instructions.

If Docker reports `no space left on device`, free Docker storage or use a
larger data partition. Some hosts also need the following kernel and file
descriptor limits for large capture runs:

```bash
# Apply until reboot
sudo sysctl -w vm.max_map_count=262144

# Persist across reboots
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

Append these lines to `/etc/security/limits.conf`, then log out and back in (or
reboot) before a full run:

```text
* soft nofile 1048576
* hard nofile 1048576
```

## Run and validate

Validate every bundled scene without starting Docker:

```bash
poetry run python validate_construction_inputs.py
```

Run one scene, or run the official batch:

```bash
BATCH=1 poetry run python main.py --config-path example/python-demo \
  --output-path results/python-demo
bash build.sh
```

`build.sh` writes `results/<scenario>/<timestamp>/raw` and `index` below this
stage directory. Keep the current directory at the stage root when invoking
it so that `example/`, `results/`, and the capture helpers resolve correctly.
The single-scene command above uses the same layout. Without `--output-path`,
`main.py` writes to `results/<timestamp>/` directly.

The help and configuration-validation commands above do not start Docker.
Keep the bundled runtime inputs together:

- `example/`: scenario definitions, Dockerfiles, Compose files, services,
  action drivers, hidden build-context files, fixtures, and auxiliary multi-jump inputs;
- `hook/`, `modify/`, `sysdig_rules/`: capture and instrumentation support,
  including the hook source, build scripts, and runtime artifacts used by scenario Dockerfiles;
- `print_fields_new.lua`: required by `load_logs.py` when converting Sysdig captures;
- `analyze.py`: produces derived `raw/index` run products after capture;
- `pyproject.toml` and `poetry.lock`: Python environment definition.

<details>
<summary>glibc hook IP remapping</summary>

The attacker-IP mapping used by the glibc hook is
`modify/hook_glibc_attacker/ip_list.h`. `modify/hook_glibc_attacker/configure.py`
generates this header from `config_attack.py`, which the builder populates
with the scenario's IP remapping. The C hook replaces matching IPv4 destination
addresses in `connect`/`sendto` calls. The header is generated as part of the
hook build when the scenario requires it.

</details>

Some bundled scenarios contain Python 2 proof-of-concept code. Run
those programs only inside their declared Docker environment.

This stage creates the input consumed by stage 02.

## Acknowledgements

The construction framework in this directory is adapted from
[AutoLabel](https://github.com/autolabel-open/autolabel) (Peng et al.,
USENIX Security 2025). We thank its authors for releasing the framework and
Docker images.

<details>
<summary>Upstream attribution and license</summary>

AutoLabel's code, documentation, and Docker images are
archived at [doi:10.5281/zenodo.15540310](https://doi.org/10.5281/zenodo.15540310),
Copyright (C) 2025 by Yihao Peng, Tongxin Zhang, Jieshao Lai, Yuxuan Zhang,
Yiming Wu, Hai Wan, and Xibin Zhao, and licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). SecLog modifies and
extends this code, including the scenario configurations and additional
indexing, export, and validation scripts.

</details>
