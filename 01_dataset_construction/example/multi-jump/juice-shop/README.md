# Juice Shop Example

## Start

The multi-jump scenario is configured in `../scene.yml`. Run it from
`01_dataset_construction/`:

```bash
BATCH=1 poetry run python main.py --config-path example/multi-jump \
  --output-path results/multi-jump
```

The local `start.py` is an optional configuration generator. Running
`python start.py {x} {y}` from this directory overwrites the local `scene.yml`
with x normal bots and y attack bots. It does not start Docker or modify the
parent multi-jump configuration.

## References

- PoC: [OWASP Juice Shop](https://help.owasp-juice.shop/appendix/solutions.html)
- Homepage: https://owasp.org/www-project-juice-shop/
