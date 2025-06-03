# Usage: go-continuous-fuzz

## Configuration Options

You can configure **go-continuous-fuzz** using either environment variables or command-line flags. All options are listed below:

| Environment Variable | Command-line Flag     | Description                                                                             | Required | Default |
| -------------------- | --------------------- | --------------------------------------------------------------------------------------- | -------- | ------- |
| `NUM_WORKERS` | `--num_workers`     | Number of concurrent fuzzing workers                                                  | No       | 1       |
| `PROJECT_SRC_PATH`   | `--project_src_path`  | Git repo URL of the project to fuzz                                                     | Yes      | —       |
| `S3_BUCKET_NAME`   | `--s3_bucket_name`  | Name of the AWS S3 bucket where the seed corpus will be stored                                               | Yes      | —       |
| `SYNC_FREQUENCY`          | `--sync_frequency`         | Duration between consecutive fuzzing cycles                                                                | No       | 120s    |
| `FUZZ_PKGS_PATH`     | `--fuzz_pkgs_path`    | Comma-separated list of Go package path to fuzz, relative to the project root directory | Yes      | —       |
| `FUZZ_RESULTS_PATH`  | `--fuzz_results_path` | Path to store fuzzing results                                                           | Yes      | —       |

**Repository URL formats:**

- Private: `https://oauth2:PAT@github.com/OWNER/REPO.git`
- Public: `https://github.com/OWNER/REPO.git`

## How It Works

1. **Configuration:**  
   Set the required environment variables or pass the corresponding flags to configure the fuzzing process.

2. **Fuzz Target Detection:**  
   The tool automatically detects all available fuzz targets in the provided project repository.

3. **Fuzzing Execution:**  
   Go's native fuzzing is executed on each detected fuzz target. The number of concurrent fuzzing workers is controlled by the `NUM_WORKERS` variable.

4. **Corpus Persistence:**  
   For each fuzz target, the fuzzing engine generates an input corpus. Depending on the `FUZZ_RESULTS_PATH` setting, this corpus is saved to the specified directory, ensuring that the test inputs are preserved and can be reused in future runs.

## Running go-continuous-fuzz

1. **Clone the Repository**

   ```bash
   git clone github.com/go-continuous-fuzz/go-continuous-fuzz.git
   cd go-continuous-fuzz
   ```

2. **Set Configuration paramaters**  
   You can use environment variables:

   ```bash
   export NUM_WORKERS=<number_of_workers>
   export PROJECT_SRC_PATH=<project_repo_url>
   export S3_BUCKET_NAME=<bucket_name>
   export SYNC_FREQUENCY=<time>
   export FUZZ_PKGS_PATH=<target_package>
   export FUZZ_RESULTS_PATH=<path/to/file>
   ```

   Or pass flags directly:

   ```bash
     --project_src_path=<project_repo_url>
     --s3_bucket_name=<bucket_name>
     --fuzz_results_path=<path/to/file>
     --fuzz_pkgs_path=<path/to/corpus/dir>
     --sync_frequency=<time>
     --num_workers=<number_of_workers>
   ```

3. **Run the Fuzzing Engine:**  
   With your environment configured, start the fuzzing process. Run:

   ```bash
   make run
   ```

   Or pass flags directly:

   ```bash
   make run ARGS=<flags>
   ```

## Additional Information

- You can mix environment variables and command-line flags; flags take precedence.
- For more advanced usage, including Docker integration and running tests, see [INSTALL.md](./INSTALL.md).
