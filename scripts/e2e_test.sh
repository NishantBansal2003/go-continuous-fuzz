#!/bin/bash
set -euo pipefail # Enable strict error handling
set -x            # Enable command tracing

# =============================================================================
# CONFIGURATION
# =============================================================================
# Environment variables for fuzzing process configuration
export PROJECT_SRC_PATH="https://github.com/NishantBansal2003/go-fuzzing-example.git"
export CORPUS_DIR_PATH="$HOME/corpus"
export FUZZ_TIME="15m"
export FUZZ_PKGS_PATH="parser,stringutils"
export FUZZ_RESULTS_PATH="$HOME/fuzz_results"

# Temporary Variables
readonly PROJECT_BRANCH="fuzz-example"
readonly PROJECT_DIR="$HOME/project"

# Fuzz target definitions (package:function)
readonly FUZZ_TARGETS=(
  "parser:FuzzParseComplex"
  "parser:FuzzEvalExpr"
  "stringutils:FuzzUnSafeReverseString"
  "stringutils:FuzzReverseString"
)

# =============================================================================
# FUNCTION DEFINITIONS
# =============================================================================

# Counts the number of test inputs in a corpus directory
# Arguments:
#   $1 - Package name
#   $2 - Function name
# Returns: Number of input files
count_corpus_inputs() {
  local pkg="$1"
  local func="$2"

  local dir="${CORPUS_DIR_PATH}/${pkg}/testdata/fuzz/${func}"

  if [[ -d "$dir" ]]; then
    local num_inputs
    num_inputs=$(ls "$dir" | wc -l | xargs)
    echo $num_inputs
  else
    echo 0
  fi
}

# Measures the code coverage for a fuzz target
# Arguments:
#   $1 - Package name
#   $2 - Function name
# Returns: Coverage percentage value
measure_fuzz_coverage() {
  local pkg="$1"
  local func="$2"
  local coverage_result

  pushd "${PROJECT_DIR}/${pkg}" >/dev/null

  # Enable Go fuzzing debug output
  export GODEBUG="fuzzdebug=1"

  # Count existing corpus inputs
  local num_inputs
  num_inputs=$(count_corpus_inputs "$pkg" "$func")

  # Incrementing to account for the seed corpus entry; otherwise, we won't get any coverage bits.
  ((num_inputs++))

  # Run coverage measurement
  coverage_result=$(go test -run="^${func}$" -fuzz="^${func}$" \
    -fuzztime="${num_inputs}x" \
    -test.fuzzcachedir="${CORPUS_DIR_PATH}/${pkg}/testdata/fuzz" |
    grep "initial coverage bits:" | grep -oE "[0-9]+$" || echo 0)

  popd >/dev/null

  echo "$coverage_result"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

# Clone the target repository
echo "🚀 Cloning project repository..."
git clone --branch "$PROJECT_BRANCH" --single-branch --depth 1 \
  "$PROJECT_SRC_PATH" "$PROJECT_DIR"

# Initialize data stores
declare -A initial_input_counts
declare -A initial_coverage_metrics
declare -A final_input_counts
declare -A final_coverage_metrics

# Capture initial corpus state
echo "📊 Recording initial corpus state..."
for target in "${FUZZ_TARGETS[@]}"; do
  IFS=':' read -r pkg func <<<"$target"
  echo "  - $pkg/$func"
  initial_input_counts["$target"]=$(count_corpus_inputs "$pkg" "$func")
  initial_coverage_metrics["$target"]=$(measure_fuzz_coverage "$pkg" "$func")
done

# Execute fuzzing process
echo "🔍 Starting fuzzing process (timeout: $FUZZ_TIME)..."
timeout -s INT --preserve-status "$FUZZ_TIME" make run || {
  status=$?
  # Handle timeout (SIGINT/130) as expected termination
  if [[ $status -ne 130 ]]; then
    echo "❌ Fuzzing exited with unexpected error: $status"
    exit $status
  fi
}

# Capture final corpus state
echo "📈 Recording final corpus state..."
for target in "${FUZZ_TARGETS[@]}"; do
  IFS=':' read -r pkg func <<<"$target"
  echo "  - $pkg/$func"
  final_input_counts["$target"]=$(count_corpus_inputs "$pkg" "$func")
  final_coverage_metrics["$target"]=$(measure_fuzz_coverage "$pkg" "$func")
done

# Validate corpus growth
echo "🔎 Validating corpus growth..."
for target in "${FUZZ_TARGETS[@]}"; do
  initial_count=${initial_input_counts["$target"]}
  final_count=${final_input_counts["$target"]}

  if [[ $final_count -lt $initial_count ]]; then
    echo "❌ ERROR: $target regressed - inputs decreased from $initial_count to $final_count"
    exit 1
  fi
done

# Validate coverage metrics
echo "✅ Validating coverage metrics..."
for target in "${FUZZ_TARGETS[@]}"; do
  initial_cov=${initial_coverage_metrics["$target"]}
  final_cov=${final_coverage_metrics["$target"]}

  if [[ $final_cov -lt $initial_cov ]]; then
    echo "❌ ERROR: $target coverage decreased from $initial_cov to $final_cov"
    exit 1
  fi
done

# Verify crash reports
echo "📄 Checking crash reports..."
required_crashes=(
  "$FUZZ_RESULTS_PATH/FuzzParseComplex_failure.log"
  "$FUZZ_RESULTS_PATH/FuzzUnSafeReverseString_failure.log"
)

for crash_file in "${required_crashes[@]}"; do
  if [[ ! -f "$crash_file" ]]; then
    echo "❌ ERROR: Missing crash report: $crash_file"
    exit 1
  fi

  if ! grep -q "go test fuzz v1" "$crash_file"; then
    echo "❌ ERROR: Invalid crash report format in $crash_file"
    exit 1
  fi
done

# Cleanup resources
echo "🧹 Cleaning up resources..."
rm -rf "$PROJECT_DIR"
rm -rf "$FUZZ_RESULTS_PATH"

echo "🎉 All validations completed successfully!"
exit 0
