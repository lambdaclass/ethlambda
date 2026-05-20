#!/usr/bin/env bash

set -euo pipefail

results_dir="${1:-src/results}"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to parse Hive results but was not found in PATH"
  exit 1
fi

if [ ! -d "${results_dir}" ]; then
  echo "Hive results directory '${results_dir}' not found"
  exit 1
fi

shopt -s nullglob
json_files=("${results_dir}"/*.json)
shopt -u nullglob

if [ "${#json_files[@]}" -eq 0 ]; then
  echo "No Hive JSON result files found in ${results_dir}"
  exit 1
fi

failures=0
failed_logs_root="${results_dir}/failed_logs"
rm -rf "${failed_logs_root}"
mkdir -p "${failed_logs_root}"

for json_file in "${json_files[@]}"; do
  if [[ "${json_file}" == *"hive.json" ]]; then
    continue
  fi

  suite_name="$(jq -r '.name // empty' "${json_file}")"
  suite_label="${suite_name:-$(basename "${json_file}" .json)}"
  failed_cases="$(jq '[.testCases[]? | select(.summaryResult.pass != true)] | length' "${json_file}")"

  if [ "${failed_cases}" -eq 0 ]; then
    continue
  fi

  failures=$((failures + failed_cases))
  echo "Detected ${failed_cases} failing Hive test case(s) in ${suite_label}"

  failure_list="$(
    jq -r '
      .testCases[]?
      | select(.summaryResult.pass != true)
      | . as $case
      | ($case.summaryResult // {}) as $summary
      | ($summary.message // $summary.reason // $summary.error // "") as $message
      | "- " + ($case.name // "unknown test")
        + (if $message != "" then ": " + $message else "" end)
    ' "${json_file}"
  )"

  printf '%s\n' "${failure_list}"

  suite_slug="$(printf '%s' "${suite_label}" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9._-]+/-/g; s/^-//; s/-$//')"
  suite_dir="${failed_logs_root}/${suite_slug:-suite}"
  mkdir -p "${suite_dir}"

  cp "${json_file}" "${suite_dir}/"
  printf '%s\n\n%s\n' "Detected ${failed_cases} failing Hive test case(s) in ${suite_label}" "${failure_list}" > "${suite_dir}/failed-tests.txt"

  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      echo "### Hive failures: ${suite_label}"
      printf '%s\n' "${failure_list}"
      echo
    } >> "${GITHUB_STEP_SUMMARY}"
  fi
done

if [ "${failures}" -gt 0 ]; then
  echo "Hive reported ${failures} failing test case(s) in total"
  exit 1
fi

echo "Hive reported no failing test cases."
