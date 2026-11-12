# IndexCase

Trace malware propagation and identify patient zero in Active Directory.

IndexCase will read exported Windows event logs (Security, System, Sysmon),
find every host showing a given malware's behaviour, link those hosts by
authentication plus remote-execution evidence, and rank the most likely
origin, citing the events behind every link.

## Status

Early work in progress.

- [x] Project setup and CI
- [x] Read `.evtx` files and `.jsonl` exports
- [x] Normalized event schema, stored as Parquet
- [x] Event mappers for Security, System and Sysmon
- [x] IP to host resolution
- [ ] Malware profiles and host matching
- [ ] Edge reconstruction (SMB + service, WMI, scheduled task)
- [ ] Patient zero ranking and report

## Development

```
python -m venv .venv
.venv\Scripts\activate          # Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
ruff check .
```

## License

Apache 2.0
