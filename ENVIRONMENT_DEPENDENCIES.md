# SecLog Environment Dependencies

## Supported platform

- Ubuntu Linux with Bash.
- Python 3.11.
- Poetry (the dataset-construction project is defined by
  `01_dataset_construction/pyproject.toml` and `poetry.lock`).
- Conda is optional and may be used to create an isolated Python 3.11
  environment.

## Stage 01: 01_dataset_construction

Dependencies for Docker scenario execution and raw/index generation.

### System packages

Install the following Ubuntu packages:

```text
ca-certificates curl gzip nano git jq build-essential pkg-config
python3-dev zlib1g-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev
linux-headers-$(uname -r) dkms docker.io docker-compose-plugin tshark
tcpdump conntrack util-linux iproute2 net-tools procps
```

The standalone `docker-compose` package is optional for scenarios that require
the `docker-compose` command instead of the Compose plugin.

### Capture tools and privileges

- Docker Engine and Docker Compose.
- Sysdig.
- `tcpdump`, `tshark`, and `conntrack`.
- `nsenter` from `util-linux`.
- Linux headers and DKMS when required by the capture installation.
- Root or sudo privileges for system and network capture.
- Docker scenario images used by `01_dataset_construction/example/`.

### Python dependencies

The stage-01 runtime uses the core construction packages listed in the full
package set below, together with the scenario-service packages when a bundled
scene requires them.

### Build procedure

Download or clone this project, then run the following commands from its root
directory:

```bash
cd 01_dataset_construction
```

Install Docker and the common host tools:

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

Install Poetry and the Python environment from the release-stage project:

```bash
pip install --user poetry
poetry env use python3.11
poetry install
poetry run python -c "print('ok')"
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

If Docker reports `no space left on device`, provide sufficient Docker and
filesystem space before retrying. Configure the kernel map count when needed:

```bash
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

Set the file-descriptor limits in `/etc/security/limits.conf`:

```text
* soft nofile 1048576
* hard nofile 1048576
```

Log out and back in, or reboot, after changing the limits. Run the dataset
builder from the stage directory:

```bash
bash build.sh
```

## Stages 02-05: downstream processing and evaluation

Dependencies for `02_attack_chain_construction`, `03_dataset_release_generation`,
`04_benchmark_window_selection`, and
`05_benchmark_annotation_review_evaluation`.

### Python packages

The full environment uses the following package ranges:

```text
loguru>=0.7.2,<0.8.0
rich>=13.9.4,<14.0.0
typer>=0.13.1,<0.14.0
docker>=7.1.0,<8.0.0
psutil>=6.1.0,<7.0.0
python-dateutil>=2.9.0.post0,<3.0.0
tqdm>=4.67.0,<5.0.0
pydantic>=2.10.1,<3.0.0
PyYAML>=6.0.2,<7.0.0
scapy>=2.6.1,<3.0.0
pydantic-settings>=2.6.1,<3.0.0
pydantic-settings-yaml>=0.2.0,<1.0.0
msgpack>=1.1.0,<2.0.0
requests>=2.32.0,<3.0.0
aiohttp>=3.11.0,<4.0.0
httpx>=0.28.0,<1.0.0
fastapi>=0.115.0,<1.0.0
uvicorn[standard]>=0.34.0,<1.0.0
hypercorn>=0.17.0,<1.0.0
Flask>=3.1.0,<4.0.0
beautifulsoup4>=4.12.0,<5.0.0
lxml>=5.0.0,<6.0.0
termcolor>=2.4.0,<3.0.0
pycryptodome>=3.20.0,<4.0.0
pyasn1>=0.6.0,<1.0.0
pyminizip>=0.2.6,<1.0.0
streamlit>=1.45.0,<2.0.0
openai>=1.0.0,<3.0.0
anthropic>=0.40.0,<1.0.0
matplotlib>=3.9.0,<4.0.0
numpy>=1.26.0,<3.0.0
pandas>=2.2.0,<3.0.0
orjson>=3.10.0,<4.0.0
pytest>=8.0.0,<9.0.0
```

Create an isolated environment, then install the listed packages with pip:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install \
  "loguru>=0.7.2,<0.8.0" "rich>=13.9.4,<14.0.0" \
  "typer>=0.13.1,<0.14.0" "docker>=7.1.0,<8.0.0" \
  "psutil>=6.1.0,<7.0.0" "python-dateutil>=2.9.0.post0,<3.0.0" \
  "tqdm>=4.67.0,<5.0.0" "pydantic>=2.10.1,<3.0.0" \
  "PyYAML>=6.0.2,<7.0.0" "scapy>=2.6.1,<3.0.0" \
  "pydantic-settings>=2.6.1,<3.0.0" \
  "pydantic-settings-yaml>=0.2.0,<1.0.0" "msgpack>=1.1.0,<2.0.0" \
  "requests>=2.32.0,<3.0.0" "aiohttp>=3.11.0,<4.0.0" \
  "httpx>=0.28.0,<1.0.0" "fastapi>=0.115.0,<1.0.0" \
  "uvicorn[standard]>=0.34.0,<1.0.0" "hypercorn>=0.17.0,<1.0.0" \
  "Flask>=3.1.0,<4.0.0" "beautifulsoup4>=4.12.0,<5.0.0" \
  "lxml>=5.0.0,<6.0.0" "termcolor>=2.4.0,<3.0.0" \
  "pycryptodome>=3.20.0,<4.0.0" "pyasn1>=0.6.0,<1.0.0" \
  "pyminizip>=0.2.6,<1.0.0" "streamlit>=1.45.0,<2.0.0" \
  "openai>=1.0.0,<3.0.0" "anthropic>=0.40.0,<1.0.0" \
  "matplotlib>=3.9.0,<4.0.0" "numpy>=1.26.0,<3.0.0" \
  "pandas>=2.2.0,<3.0.0" "orjson>=3.10.0,<4.0.0" \
  "pytest>=8.0.0,<9.0.0"
```

### Package roles

- Core construction: `loguru`, `rich`, `typer`, `docker`, `psutil`,
  `python-dateutil`, `tqdm`, `pydantic`, `PyYAML`, `scapy`,
  `pydantic-settings`, and `msgpack`.
- Scenario services and helpers: `requests`, `aiohttp`, `httpx`, `fastapi`,
  `uvicorn`, `hypercorn`, `Flask`, `beautifulsoup4`, `lxml`, `termcolor`,
  `pycryptodome`, `pyasn1`, and `pyminizip`.
- Release and evaluation utilities: `orjson`, `numpy`, `pandas`, and
  `matplotlib`.
- Review UI: `streamlit` and `pandas`.
- API-backed annotation and evaluation: `openai` and `anthropic`.
- Tests and smoke checks: `pytest`.

### Runtime configuration dependencies

API-backed components require provider configuration through environment
variables or an interactive configuration mechanism. No API package requires
credentials at installation time.
