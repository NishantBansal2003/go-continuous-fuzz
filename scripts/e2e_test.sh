#!/bin/bash

set -x

# Specify the environment variables for the fuzzing process
export PROJECT_SRC_PATH="https://github.com/NishantBansal2003/go-fuzzing-example.git"
export CORPUS_DIR_PATH="~/corpus"
export FUZZ_TIME="14m"
export FUZZ_PKGS_PATH="parser,stringutils"
export FUZZ_RESULTS_PATH="~/fuzz_results"

# Run the make command with a 15-minute timeout
timeout -s INT --preserve-status 15m make run
EXIT_STATUS=$?

# If make run failed (not timeout and SIGINT), exit with error
if [ $EXIT_STATUS -ne 0 ] && [ $EXIT_STATUS -ne 130 ]; then
  echo "❌ The operation exited with status $EXIT_STATUS."
  exit $EXIT_STATUS
fi

# Check if the $HOME/fuzz_results directory exists
if [ -d "$HOME/fuzz_results" ]; then
  echo "✅ Fuzzing process completed successfully."
else
  echo "❌ Fuzzing process failed."
  exit 1
fi

# Cleanup: Delete the $HOME/fuzz_results directory
rm -rf "$HOME/fuzz_results"