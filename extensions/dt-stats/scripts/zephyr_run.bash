#! /usr/bin/env bash

# A basic script that sets up zephyr and then runs stats on it
#

# Get path to script directory a la
# https://stackoverflow.com/questions/59895/how-do-i-get-the-directory-where-a-bash-script-is-located-from-within-the-script/246128#246128
DT_SCRIPTS=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
# Then back out of it to get the path to the styx repo
STYX=$(dirname "$(dirname "$(dirname "$DT_SCRIPTS")")")

source "$STYX/venv/bin/activate"
if [[ ! $(command -v west) ]] then
    echo "west not found. Activate python venv"
else
    echo "west found."
fi

west init -m https://github.com/zephyrproject-rtos/zephyr --mr main zephyrproject
cd zephyrproject
ZEPH_PROJ_DIR=$(pwd)
west update

# Cd so we can "cargo r"
cd $STYX
direnv exec ./ cargo r -p dt-stats -- --zephyr-proj-dir $ZEPH_PROJ_DIR $ZEPH_PROJ_DIR/zephyr/boards/
