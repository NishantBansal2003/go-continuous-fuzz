# go-continuous-fuzz

Continuous fuzzing of Go projects.

go-continuous-fuzz is a Go native fuzzing tool that automatically detects and runs fuzz targets in the repository. It is designed to run multiple fuzzing processes concurrently and to persist the generated input corpus, helping continuously test and improve the codebase's resilience.

## Features

- **Automatic Fuzz Target Detection:** Scans the repository and identifies all available fuzz targets.
- **Concurrent Fuzzing:** Runs multiple fuzzing processes concurrently, with the default set to the number of available CPU cores.
- **Customizable Execution:** Configure the duration and target package for fuzzing with environment variables.
- **Corpus Persistence:** Saves the input corpus for each fuzz target to a specified local directory, ensuring that the test cases are preserved for future runs.

## Deployment & Execution

go-continuous-fuzz is designed with built-in coordination logic, eliminating the need for external CI frameworks like Jenkins or Buildbot. It can be deployed as a long-running service on any cloud instance (e.g., AWS EC2, GCP Compute Engine, or DigitalOcean Droplet). Once initiated, the application autonomously manages its execution cycles, running continuously and restarting the fuzzing process at intervals defined by the `FUZZ_TIME` environment variable.

## For more information, see:

1. [INSTALL.md](docs/INSTALL.md)
2. [USAGE.md](docs/USAGE.md)
