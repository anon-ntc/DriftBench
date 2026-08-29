# Rebuild and validation scripts

Run command from the package root:

```bash
python3 scripts/rebuild.py
```

`rebuild.py` reconstructs candidate membership and all derived result tables from packaged inputs. It writes deterministic UTF-8 CSV files with stable ordering. An optional `--output-root` argument writes the generated files into an empty comparison directory.

The script uses the Python standard library and require no network access.
