# Styx on Guix

This repository is exposed as a [guix channel](https://guix.gnu.org/manual/en/html_node/Channels.html), so you could
add it to your local guix channels in order to build the packages, but we do not do that yet.

Currently if you are using **direnv**, then you can allow the root styx directory (`direnv allow .` in the
root `styx-emulator` directory). This exposes 2 shell commands `bootstrap-guix` and `enter-guix`.

Note that right now there are some dependencies that need to be built locally so the bootstrap might take a second.
There is an upstream in progress for most of them at the moment, but the rust branch only gets merged
into guix master every once in awhile.

**NOTE**: if the you selected "no" for accepting upstream mirrors during guix install, or otherwise
 removed `bordeaux.guix.gnu.org` from the default substituters, you will need to adjust the
 `STYX_GUIX_SUBSTITUTES`
## Current guix workflow

``` sh
(styx-root) $ direnv allow .
(styx-root) $ bootstrap-guix # optional, `enter-guix` will run bootstrap if it has not been done yet
(styx-root) $ enter-guix
[guix-env] $ just test
```

## Customizing guix

The main attraction to guix is the ability to completely customize and transform your personal linux
system. In order to retain the high level of customization many people are used to, the `guix` workflow
can be tweaked entirely with environment customization's via `.local.env` in the top level of the `styx-emulator`
repository. It is **recommended** to read the sections on guix shell (and the `./envrc-utils.bash`) before
modifying the following environment variables:

- `GUILE_LOAD_PATH`
  - used by guile (the language guix is written in to modify the import path)
  - useful for adding custom tools to the import path
- `STYX_GUIX_SUBSTITUTES`
  - list of substitute servers to use, useful to privately use your own without
    accidentally adding them to git etc.
- `__GUIX_LOAD_PATH`
  - like the guile load path, except for the guix package importer
- `__GUIX_PREFIX`
  - the "prefix" of all scripted guix commands, useful to pin the package set to a
    specific commit to ensure reproducibility
- `__GUIX_SHELL_MANIFEST`
  - path to the build environment package manifest to use
- `__GUIX_LINK_DIR`
  - used to store gc roots etc
- `__GUIX_SHELL_ARGS`
  - any other args to pass `guix shell`, by default it strips the env, enters a container with guix and
    the dependencies, and enables network access to the container
- `__GUIX_PRESERVED_ENV_VARS`
  - list of environment variables to keep in the sandboxed container
- `__GUIX_SHELL_SHARE_DIRS`
  - list of directories to share with RW permissions with the container
- `__GUIX_SHELL_EXPORT_DIRS`sandboxed con
  - list of directories to share with RO permissions with the container

## Why guix
guix (as opposed to nix) is able to build our codebase without patching anything!
As a combined cxx/c/rust codebase nix is unable to package LLVM + necessary libraries,
or give the proper build necessities without heavily patching the nixpkgs tree in a
way that would require almost a full rebuild of the entire nix package set.

guix does it without modification and on the first try, most of which is possible due
to guix requiring all mainline packages be built from source (as opposed to nix). The
plus side of this is that there is little institutional knowledge required about the
internals of guix (unlike nix would have required), meaning that a tool can remain a
tool, not a heavily maintained piece of internal infrastructure requiring dedicated
effort.
