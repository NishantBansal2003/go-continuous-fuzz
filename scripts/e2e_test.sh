#!/bin/bash

set -eux

# ====== CONFIGURATION ======

# Temporary Variables
readonly PROJECT_SRC_PATH="https://github.com/go-continuous-fuzz/go-fuzzing-example.git"
readonly SYNC_FREQUENCY="3m"
readonly MAKE_TIMEOUT="4m"

# Use test workspace directory
readonly TEST_WORKDIR="var/lib/go-continuous-fuzz"
readonly PROJECT_DIR="${TEST_WORKDIR}/project"
readonly CORPUS_DIR_NAME="go-fuzzing-example_corpus"
readonly CORPUS_ZIP_NAME="${CORPUS_DIR_NAME}.zip"
readonly CORPUS_DIR_PATH="${TEST_WORKDIR}/${CORPUS_DIR_NAME}"
readonly FUZZ_RESULTS_PATH="${TEST_WORKDIR}/fuzz_results"
readonly BUCKET_NAME="test-go-continuous-fuzz-bucket"

mkdir -p ${TEST_WORKDIR}

# Command-line flags for fuzzing process configuration
ARGS="\
--project.src-repo=${PROJECT_SRC_PATH} \
--project.s3-bucket-name=${BUCKET_NAME} \
--fuzz.sync-frequency=${SYNC_FREQUENCY} \
--fuzz.results-path=${FUZZ_RESULTS_PATH} \
--fuzz.num-workers=3 \
--fuzz.pkgs-path=parser \
--fuzz.pkgs-path=stringutils \
--fuzz.pkgs-path=tree"

# Non-crashing fuzz target definitions (package:function)
readonly NON_CRASHING_FUZZ_TARGETS=(
  "parser:FuzzEvalExpr"
  "stringutils:FuzzReverseString"
)

# Crashing fuzz target definitions (function)
readonly CRASHING_FUZZ_TARGETS=(
  "FuzzParseComplex"
  "FuzzUnSafeReverseString"
  "FuzzBuildTree"
)

# === K8S SETUP ===
readonly AWS_SECRET_NAME="aws-creds"
readonly HELM_RELEASE_NAME="go-continuous-fuzz"
readonly HELM_CHART_PATH="./go-continuous-fuzz-chart"
readonly K8S_NAMESPACE="default"

make docker
kind load docker-image go-continuous-fuzz

kubectl delete secret ${AWS_SECRET_NAME} --ignore-not-found
kubectl create secret generic ${AWS_SECRET_NAME} \
  --from-literal=AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID}" \
  --from-literal=AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY}" \
  --from-literal=AWS_REGION="${AWS_REGION}"

helm upgrade --install "${HELM_RELEASE_NAME}" "${HELM_CHART_PATH}" \
  --namespace "${K8S_NAMESPACE}"

kubectl apply -f ./manifests/

# Ensure that resources are cleaned up when the script exits
trap 'echo "Cleaning up resources..."; aws s3 rb "s3://${BUCKET_NAME}" --force' EXIT

# ====== FUNCTION DEFINITIONS ======

# Counts the number of test inputs in a corpus directory
# Arguments:
#   $1 - Package name
#   $2 - Function name
# Returns: Number of input files
count_corpus_inputs() {
  local pkg="$1"
  local func="$2"

  local dir="${CORPUS_DIR_PATH}/${pkg}/testdata/fuzz/${func}"

  if [[ -d "${dir}" ]]; then
    local num_inputs=$(ls "${dir}" | wc -l)
    echo ${num_inputs}
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

  cd "${PROJECT_DIR}/${pkg}"

  # Enable Go fuzzing debug output
  export GODEBUG="fuzzdebug=1"

  # Count existing corpus inputs
  local num_inputs=$(count_corpus_inputs "${pkg}" "${func}")

  # Run coverage measurement
  coverage_result=$(go test -run="^${func}$" -fuzz="^${func}$" \
    -fuzztime="${num_inputs}x" \
    -test.fuzzcachedir="${CORPUS_DIR_PATH}/${pkg}/testdata/fuzz" |
    grep "initial coverage bits:" | grep -oE "[0-9]+$")

  echo "${coverage_result}"
}

# ====== MAIN EXECUTION ======

# Clone the target repository
echo "Cloning project repository..."
git clone "${PROJECT_SRC_PATH}" "${PROJECT_DIR}"

# Download and extract only the seed_corpus directory from the project tarball
echo "Downloading seed corpus..."
mkdir -p ${CORPUS_DIR_PATH}
curl -L https://codeload.github.com/go-continuous-fuzz/go-fuzzing-example/tar.gz/main |
  tar -xz --strip-components=2 -C ${CORPUS_DIR_PATH} go-fuzzing-example-main/seed_corpus

# Create the S3 bucket and upload the zipped corpus
echo "Creating S3 bucket and uploading corpus..."
aws s3 mb s3://${BUCKET_NAME}
(
  cd "${TEST_WORKDIR}"
  zip -r ${CORPUS_ZIP_NAME} ${CORPUS_DIR_NAME}
  aws s3 cp ${CORPUS_ZIP_NAME} s3://${BUCKET_NAME}/${CORPUS_ZIP_NAME}
)

# Initialize data stores
declare -A initial_input_counts
declare -A initial_coverage_metrics
declare -A final_input_counts
declare -A final_coverage_metrics

# Capture initial corpus state
echo "Recording initial corpus state..."
for target in "${NON_CRASHING_FUZZ_TARGETS[@]}"; do
  IFS=':' read -r pkg func <<<"${target}"
  echo "  - ${pkg}/${func}"
  initial_input_counts["${target}"]=$(count_corpus_inputs "${pkg}" "${func}")
  initial_coverage_metrics["${target}"]=$(measure_fuzz_coverage "${pkg}" "${func}")
done

# Execute fuzzing process
echo "Starting fuzzing process (timeout: ${MAKE_TIMEOUT})..."
mkdir -p "${FUZZ_RESULTS_PATH}"
MAKE_LOG="${FUZZ_RESULTS_PATH}/make_run.log"

echo "Waiting for pod to be ready..."
kubectl wait --for=condition=Ready pod/go-continuous-fuzz-pod --timeout=60s

# Run make run under timeout, capturing stdout+stderr into MAKE_LOG.
echo "Streaming logs from pod (timeout: ${MAKE_TIMEOUT})..."
kubectl logs -f go-continuous-fuzz-pod &

timeout -s INT --preserve-status "${MAKE_TIMEOUT}" kubectl exec go-continuous-fuzz-pod -- pkill -SIGINT -f go-continuous-fuzz
status=${PIPESTATUS[0]}

# Handle exit codes:
#   130 → timeout sent SIGINT; treat as expected termination
#   any other non-zero → unexpected error
if [[ ${status} -ne 130 ]]; then
  echo "❌ Fuzzing exited with unexpected error (status: ${status})."
  exit "${status}"
fi

mkdir -p ${TEST_WORKDIR}

kubectl logs go-continuous-fuzz-pod >> "${MAKE_LOG}"
kubectl delete pod go-continuous-fuzz-pod --ignore-not-found

# List of required patterns to check in the log
readonly REQUIRED_PATTERNS=(
  'All workers completed early; cleaning up cycle' # due to grace period
  'Successfully downloaded and unzipped corpus'
  'Successfully zipped and uploaded corpus'
  'msg="Fuzzing in Docker completed successfully" package=stringutils target=FuzzUnSafeReverseString'
  'msg="Fuzzing in Docker completed successfully" package=stringutils target=FuzzReverseString'
  'msg="Fuzzing in Docker completed successfully" package=parser target=FuzzParseComplex'
  'msg="Fuzzing in Docker completed successfully" package=parser target=FuzzEvalExpr'
  'msg="Fuzzing in Docker completed successfully" package=tree target=FuzzBuildTree'
  'Shutdown initiated during fuzzing cycle; performing final cleanup.'
  'msg="Worker starting fuzz target" workerID=1'
  'msg="Worker starting fuzz target" workerID=2'
  'msg="Worker starting fuzz target" workerID=3'
  'msg="Per-target fuzz timeout calculated" duration=1m30s'
)

# Verify that worker logs contain expected entries
echo "Verifying worker log entries in ${MAKE_LOG}..."
for pattern in "${REQUIRED_PATTERNS[@]}"; do
  if ! grep -q -- "${pattern}" "${MAKE_LOG}"; then
    echo "❌ ERROR: Missing expected log entry: ${pattern}"
    exit 1
  fi
done

# List of patterns that should NOT be present in the log
readonly FORBIDDEN_PATTERNS=(
  'level=ERROR'
  'msg="Worker starting fuzz target" workerID=4'
  'Cycle duration complete; initiating cleanup.'
  'Corpus object not found. Starting with empty corpus.'
  'warning: starting with empty corpus'
)

# Verify that worker logs do not contain forbidden entries
echo "Verifying absence of forbidden log entries in ${MAKE_LOG}..."
for pattern in "${FORBIDDEN_PATTERNS[@]}"; do
  if grep -q -- "${pattern}" "${MAKE_LOG}"; then
    echo "❌ ERROR: Unexpected log entry found: ${pattern}"
    exit 1
  fi
done

# Download updated ZIP from S3 and extract into corpus directory
echo "Downloading updated corpus from S3..."
(
  cd "${TEST_WORKDIR}"
  aws s3 cp s3://${BUCKET_NAME}/${CORPUS_ZIP_NAME} "${CORPUS_ZIP_NAME}"
  unzip -o "${CORPUS_ZIP_NAME}"
)

# Capture final corpus state
echo "Recording final corpus state..."
for target in "${NON_CRASHING_FUZZ_TARGETS[@]}"; do
  IFS=':' read -r pkg func <<<"${target}"
  echo "  - ${pkg}/${func}"
  final_input_counts["${target}"]=$(count_corpus_inputs "${pkg}" "${func}")
  final_coverage_metrics["${target}"]=$(measure_fuzz_coverage "${pkg}" "${func}")
done

# Validate corpus growth
echo "Validating corpus growth..."
for target in "${NON_CRASHING_FUZZ_TARGETS[@]}"; do
  initial_count=${initial_input_counts["${target}"]}
  final_count=${final_input_counts["${target}"]}

  if [[ ${final_count} -le ${initial_count} ]]; then
    echo "❌ ERROR: ${target} regressed - inputs decreased from ${initial_count} to ${final_count}"
    exit 1
  fi
done

# Validate coverage metrics
echo "Validating coverage metrics..."
for target in "${NON_CRASHING_FUZZ_TARGETS[@]}"; do
  initial_cov=${initial_coverage_metrics["${target}"]}
  final_cov=${final_coverage_metrics["${target}"]}

  if [[ ${final_cov} -le ${initial_cov} ]]; then
    echo "❌ ERROR: ${target} coverage decreased from ${initial_cov} to ${final_cov}"
    exit 1
  fi
done

# Verify crash reports
echo "Checking crash reports..."
# Ensure only the expected number of files exist in FUZZ_RESULTS_PATH (3 crash logs + 1 make_run.log)
num_crash_files=$(ls "${FUZZ_RESULTS_PATH}" | wc -l)
if [[ "${num_crash_files}" -ne 4 ]]; then
  echo "❌ ERROR: Unexpected number of files in ${FUZZ_RESULTS_PATH} (found: ${num_crash_files}, expected: 4)"
  exit 1
fi

for target in "${CRASHING_FUZZ_TARGETS[@]}"; do
  crash_file=""${FUZZ_RESULTS_PATH}/${target}_failure.log""
  if [[ ! -f "${crash_file}" ]]; then
    echo "❌ ERROR: Missing crash report: ${crash_file}"
    exit 1
  fi

  if ! grep -q "go test fuzz v1" "${crash_file}"; then
    echo "❌ ERROR: Invalid crash report format in ${crash_file}"
    exit 1
  fi
done

echo "✅ Fuzzing process completed successfully."
exit 0
