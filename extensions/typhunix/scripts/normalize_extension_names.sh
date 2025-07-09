#!/usr/bin/env bash
#
# Rename the Typhunix Ghidra release zip files to include the branch name and omit the date
#
# This script is intended to be run in a ci pipeline
# in the `styx-emulator/extensions/typhunix/` directory,

# Get the branch name to use
#
# check for existence of gitlab ci branch name,
# then the github branch name, then the git branch name
BRANCH_NAME="${CI_COMMIT_BRANCH}" # gitlab branch name
if [ -z "$BRANCH_NAME" ]; then
  BRANCH_NAME="${GITHUB_REF_NAME}" # github branch name
fi
if [ -z "$BRANCH_NAME" ]; then
  BRANCH_NAME="$(git rev-parse --abbrev-ref HEAD)" # git branch name
fi


# Loop through each file found by the find command
find . -type f -name 'ghidra_*_PUBLIC_*_TyphunixPlugin.zip' | while read -r file; do
  # Extract the VERSION-NUMBER part using sed
  VERSION_NUMBER=$(echo "$file" | sed -n 's|.*/ghidra_\([^_]*\)_PUBLIC_.*_TyphunixPlugin.zip|\1|p')

  # Construct the new filename, conditionally including BRANCH_NAME
  if [ -z "$BRANCH_NAME" ]; then
    new_file="ghidra_${VERSION_NUMBER}_TyphunixPlugin.zip"
  else
    new_file="ghidra_${VERSION_NUMBER}_TyphunixPlugin-${BRANCH_NAME}.zip"
  fi

  # Rename the file
  new_File_path="$(dirname "$file")/$new_file"
  mv "$file" "$new_File_path"
  echo "Renamed $file to $new_File_path"
done
