# PyTypunix

Rust binding for python. Uses `pyo3` and `maturin`.

## Development

- `make build` will create a whl file

- `make develop` will install on the fly (faster)

## Install

```bash
pip install pytyphunix
```

## CLI

`PyTyphunix` has a cli utility for viewing and saving symbols and data.

### Examples

```bash
# List pids (program identifiers)
python -m pytyphunix.cli

# Dump in default jsonl format
python -m pytyphunix.cli -s > symbols.jsonl
python -m pytyphunix.cli -d > data_types.jsonl

# Dump legacty version in json (bfin-sim format)
python -m pytyphunix.cli  --typhunix-version  0.9.0 -s -f json > symbols.json
python -m pytyphunix.cli  --typhunix-version  0.9.0 -d -f json > data_types.json
```

### Support JQ

The `jq` utility can be used to check or analyze data.

```bash
# apt-get install -y jq

# take a look at dict keys for symbols
$ python -m pytyphunix.cli -s | jq -c keys | sort -u
["address","data_size","datatype_name","function_symbol","id","name","namespace","pid","type"]

# check for duplicate data type names
Check for duplicate names:
$ python -m pytyphunix.cli -d | jq -cr .name | sort | \
  uniq -c | awk '$1 > 1' | sort -n
      2 astruct_9
      2 astruct_9 *
      2 func
      2 func *
```
