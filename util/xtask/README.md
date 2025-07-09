# Styx License Checker

This command checks all files within the wokring directory for applicable
license content. The program first checks for a present LICENSE file in the
root of the `styx-emulator` repo, then checks the top of every applicable
file in the working directory, prepending the correct license content if they
do not already match.

## Setup

### Dependencies

See [README](./README.md) for setup instructions for the repo. This command
should run properly without Just installed, however.

## Usage

To run xtask commands, the command structure is as follows:

```bash
cargo xtask <subcommand> <subcommand>
```

## Sub-Commands

### License

Navigate to the directory who's files need checking. Then, run:

```bash
cargo xtask license
```

to run the license checker program. It will print out error messages for any
files missing licenses, and prepend licenses to them.

To run the checker without modifying any files, use the `--check_only` or `-c` flag:

```bash
cargo xtask license -c
```

```bash
cargo xtask license --check_only
```

To run the checker on a specified set of files, use the optional `--files` or `-f` flag, and list
the files. For example:

```bash
cargo xtask license --files foo.py foo2.rs
```

The checker will default to checking licenses on `.py`, `.dfy`, and `.rs` files by default.

#### .licenseignore Files

To specify files/directories that the license checker should ignore without having to
list them all out in the command, create a `.licenseignore` file in the desired directory.
By adding path globs to the file, you can specify what the license checker should ignore
according to patterns rather than directly listing files.

For example, assume the following file system structure

```
`foo`
|
|--- `bar`
|    |
|    | --- `barfoo.dfy`
|
|--- `foobar.py`
```

To ignore all files in the `bar` directory, you can place a `.licenseignore` file in the `foo`
directory with the following contents:

```
/bar/*
```

and `barfoo.dfy` would no longer be checked.

This functionality is very similar to using a .gitignore file.

### Hakari

The `xtask hakari` subcommand is a wrapper around [cargo-hakari](https://crates.io/crates/cargo-hakari). Currently only wrappers for CI-like/maintenance tasks are implemented into a single "stage", with the intent that as we regularly perform packaging and delivery steps with hakari that we would add more "stages".

#### Stage: update

There are two variants to this sub-command: `xtask hakari --stage update` and `xtask hakari --stage update --dry-run`. Where the latter is more useful for checking everything is up to date, and the former is useful for bringing the repo's workspace-hack crate up to date
