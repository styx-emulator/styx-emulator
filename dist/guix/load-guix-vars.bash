#!/usr/bin/env bash
#
# Reload any guix vars that are dependant on user provided information.
#
# Usage: this script should be sourced like:
#
# ```bash
# set -a
# source <path/to/load-guix-vars.bash>
# set +a
# ```
# prefix our guix commands to ensure pinned dependencies
export __GUIX_PREFIX="guix time-machine -C ${__GUIX_PINNED_CHANNELS} --substitute-urls=${STYX_GUIX_SUBSTITUTES} -- "
