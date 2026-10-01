# Juice Shop Example

## Start

For SecLog capture, run the following from `01_dataset_construction/`:

```bash
BATCH=1 poetry run python main.py --config-path example/juice-shop \
  --output-path results/juice-shop
```

For standalone configuration generation, run `python start.py {x} {y}` from
this directory, where x is the number of normal bots and y is the number of
attack bots. This writes `bots.yml`; it does not start Docker. The standalone
`docker-compose.yml` requires the `juice-shop` and `juice-shop-bot:latest`
images and Docker Compose with support for `include`.

## References

- PoC: [OWASP Juice Shop](https://help.owasp-juice.shop/appendix/solutions.html)
- Homepage: https://owasp.org/www-project-juice-shop/
