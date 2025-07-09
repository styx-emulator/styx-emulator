#!/usr/bin/env bash
# Initialize the guix environment and expose commands to bootstrap
# and enter the guix shell environment

# exit on error
set -e

# all our guix stuff is located here
STYX_GUIX_DIR="${STYX_ROOT}/dist/guix"

#
# First, export required env variables
#

# set the default guix substituter to use, must be a comma-delimited list.
# default to only use bordeaux, the `https://ci.guix.gnu.org` datacenter
# goes down all the time
export STYX_GUIX_SUBSTITUTES="https://bordeaux.guix.gnu.org"
# add our custom utils + packages + dependencies to the guix + guile import path
export GUILE_LOAD_PATH="${STYX_GUIX_DIR}/modules:${GUILE_LOAD_PATH}"
# tell guix to load modules from styx-emulator/dist/guix/modules
export __GUIX_LOAD_PATH="${STYX_GUIX_DIR}/modules"
# path to guile file that pins the specific guix channels to use
export __GUIX_PINNED_CHANNELS="${STYX_GUIX_DIR}/channels.scm"
# path to the list of dependencies for our environment
export __GUIX_SHELL_MANIFEST="${STYX_GUIX_DIR}/shell-manifest.scm"
# path to the directory to store all our links so guix does not
# remove our built packages
export __GUIX_LINK_DIR="${STYX_GUIX_DIR}/.links"
# set the default guix shell ARGS
# N: allow nework access
# C: nspawn a linux container
# P: link guix profile to `$HOME/.guix-profile/` -- behavior in `enter-guix` depends on this
# F: emulate a linux FHS filesystem
# W: make guix available in the container
# --pure: nuke all environment variables not explicitly preserved
export __GUIX_SHELL_ARGS="-NCPFW --pure"
# comma delimited list of environment variables to keep
export __GUIX_PRESERVED_ENV_VARS=""
# comma delimited patterns of share dirs
# accepts:
# - KEY=VALUE, shares KEY at path VALUE
# - KEY, which will share it at the same path as KEY
export __GUIX_SHELL_SHARE_DIRS="$HOME/.config/direnv,$CARGO_HOME=$HOME/.cargo"
# comma delimited patterns of export dirs
# see __GUIX_SHELL_SHARE_DIRS for acceptable patterns
export __GUIX_SHELL_EXPORT_DIRS=""

#
# Add our guix scripts to the path
#
export PATH="${STYX_GUIX_DIR}/bin:${PATH}"
