#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH='' cd -- "${script_dir}/../../.." && pwd)
workflow_dir=${repo_root}/.github/workflows

errors=0
checked_build_jobs=0
declare -A checked_jobs=()

report_error() {
	echo "ERROR: $*" >&2
	((errors += 1))
}

job_names() {
	local workflow=$1

	awk '
		/^jobs:[[:space:]]*$/ { in_jobs = 1; next }
		in_jobs && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
			name = $0
			sub(/^  /, "", name)
			sub(/:.*/, "", name)
			print name
		}
	' "${workflow}"
}

job_body() {
	local workflow=$1
	local wanted_job=$2

	awk -v wanted_job="${wanted_job}" '
		/^jobs:[[:space:]]*$/ { in_jobs = 1; next }
		!in_jobs { next }
		/^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
			name = $0
			sub(/^  /, "", name)
			sub(/:.*/, "", name)
			if (in_wanted_job) exit
			in_wanted_job = (name == wanted_job)
			if (in_wanted_job) {
				found = 1
				print
			}
			next
		}
		in_wanted_job { print }
		END { if (!found) exit 3 }
	' "${workflow}"
}

job_invokes_build() {
	local body=$1

	awk '
		{
			line = $0
			sub(/^[[:space:]]*/, "", line)
			if (line ~ /^#/) next
			if (line ~ /(^|[[:space:]])make([[:space:]]|$)/ ||
			    line ~ /cluster-simulator-ci\.bash[[:space:]]+build([[:space:]]|$)/) {
				build = 1
			}
		}
		END { exit(build ? 0 : 1) }
	' <<< "${body}"
}

checkout_steps_have_lfs() {
	local body=$1

	awk '
		function finish_step() {
			if (is_checkout) {
				checkout_count++
				if (!has_lfs) missing_lfs++
			}
		}
		/^    - / {
			finish_step()
			is_checkout = 0
			has_lfs = 0
			next
		}
		/^[[:space:]]+uses:[[:space:]]*actions\/checkout@/ { is_checkout = 1 }
		is_checkout && /^[[:space:]]+lfs:[[:space:]]*true[[:space:]]*$/ { has_lfs = 1 }
		END {
			finish_step()
			exit(checkout_count > 0 && missing_lfs == 0 ? 0 : 1)
		}
	' <<< "${body}"
}

validate_lfs_job() {
	local workflow=$1
	local job=$2
	local relative_workflow=${workflow#"${repo_root}/"}
	local body

	if ! body=$(job_body "${workflow}" "${job}"); then
		report_error "${relative_workflow}: required job '${job}' is missing"
		return
	fi

	checked_jobs["${workflow}:${job}"]=1
	((checked_build_jobs += 1))
	if ! checkout_steps_have_lfs "${body}"; then
		report_error "${relative_workflow}: job '${job}' must set lfs: true on every checkout"
	fi
}

validate_no_lfs_job() {
	local workflow=$1
	local job=$2
	local relative_workflow=${workflow#"${repo_root}/"}
	local body

	if ! body=$(job_body "${workflow}" "${job}"); then
		report_error "${relative_workflow}: required job '${job}' is missing"
		return
	fi

	if rg -q '^[[:space:]]+lfs:[[:space:]]*true[[:space:]]*$' <<< "${body}"; then
		report_error "${relative_workflow}: non-build job '${job}' must not hydrate LFS"
	fi
}

validate_workflow_count() {
	local description=$1
	local expected=$2
	shift 2
	local actual=$#

	if ((actual != expected)); then
		report_error "expected ${expected} ${description} workflows, found ${actual}"
	fi
}

shopt -s nullglob
amd64_package_workflows=("${workflow_dir}"/CI-package-amd64-*.yml)
arm64_package_workflows=("${workflow_dir}"/CI-package-arm64-*.yml)
macos_workflows=("${workflow_dir}"/CI-build-macos-*.yml)

validate_workflow_count 'amd64 package' 127 "${amd64_package_workflows[@]}"
validate_workflow_count 'arm64 package' 43 "${arm64_package_workflows[@]}"
validate_workflow_count 'macOS build' 6 "${macos_workflows[@]}"

for workflow in "${amd64_package_workflows[@]}" "${arm64_package_workflows[@]}"; do
	validate_lfs_job "${workflow}" build
	validate_no_lfs_job "${workflow}" init_release
done

for workflow in "${macos_workflows[@]}"; do
	validate_lfs_job "${workflow}" build
	validate_no_lfs_job "${workflow}" init_release

	build_body=$(job_body "${workflow}" build)
	if rg -q 'PKG_CONFIG_PATH:.*openssl|OPENSSL_ROOT_DIR:' <<< "${build_body}"; then
		report_error "${workflow#"${repo_root}/"}: build job must not select system OpenSSL"
	fi
	if rg -q 'brew install .*openssl@3' <<< "${build_body}"; then
		report_error "${workflow#"${repo_root}/"}: build job must not install Homebrew openssl@3"
	fi
done

cluster_workflow=${workflow_dir}/CI-cluster-simulator.yml
validate_lfs_job "${cluster_workflow}" build
validate_no_lfs_job "${cluster_workflow}" test

mapfile -t direct_workflows < <(rg --files "${workflow_dir}" -g '*.yml' | sort)
for workflow in "${direct_workflows[@]}"; do
	[[ $(dirname -- "${workflow}") == "${workflow_dir}" ]] || continue
	while IFS= read -r job; do
		body=$(job_body "${workflow}" "${job}")
		job_invokes_build "${body}" || continue
		[[ -n ${checked_jobs["${workflow}:${job}"]+set} ]] || validate_lfs_job "${workflow}" "${job}"
	done < <(job_names "${workflow}")
done

if ((errors > 0)); then
	echo "OpenSSL LFS workflow validation failed: ${errors} error(s)" >&2
	exit 1
fi

echo "OpenSSL LFS workflow validation passed: ${checked_build_jobs} build job(s)"
