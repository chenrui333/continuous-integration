#!/usr/bin/env python3
#
# Copyright 2018 The Bazel Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import codecs
import hashlib
import json
import multiprocessing
import os
import os.path
import random
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from shutil import copyfile
from urllib.parse import urlparse
from urllib.request import url2pathname

import yaml

# Initialize the random number generator.
random.seed()

BUILDKITE_ORG = os.environ["BUILDKITE_ORGANIZATION_SLUG"]

CLOUD_PROJECT = "tf-buildkite"

SCRIPT_URL = "https://raw.githubusercontent.com/bazelbuild/continuous-integration/master/buildkite/bazelci.py?{}".format(
    int(time.time())
)

FLAKY_TESTS_BUCKET = "gs://bazel-buildkite-stats/flaky-tests-bep/"

# A map containing all supported platform names as keys, with the values being
# the platform name in a human readable format, and a the buildkite-agent's
# working directory.
PLATFORMS = {
    "centos7": {
        "name": "CentOS 7, Java 8",
        "emoji-name": ":centos: 7 (Java 8)",
        "downstream-root": "/var/lib/buildkite-agent/builds/${BUILDKITE_AGENT_NAME}/${BUILDKITE_ORGANIZATION_SLUG}-downstream-projects",
        "publish_binary": ["ubuntu1404", "centos7", "linux"],
        "docker-image": f"gcr.io/{CLOUD_PROJECT}/centos7:java8",
        "python": "python3.6",
    },
    "debian10": {
        "name": "Debian Buster, OpenJDK 11",
        "emoji-name": ":debian: Buster (OpenJDK 11)",
        "downstream-root": "/var/lib/buildkite-agent/builds/${BUILDKITE_AGENT_NAME}/${BUILDKITE_ORGANIZATION_SLUG}-downstream-projects",
        "publish_binary": [],
        "docker-image": f"gcr.io/{CLOUD_PROJECT}/debian10:java11",
        "python": "python3.7",
    },
    "ubuntu1604": {
        "name": "Ubuntu 16.04, OpenJDK 8",
        "emoji-name": ":ubuntu: 16.04 (OpenJDK 8)",
        "downstream-root": "/var/lib/buildkite-agent/builds/${BUILDKITE_AGENT_NAME}/${BUILDKITE_ORGANIZATION_SLUG}-downstream-projects",
        "publish_binary": ["ubuntu1604"],
        "docker-image": f"gcr.io/{CLOUD_PROJECT}/ubuntu1604:java8",
        "python": "python3.6",
    },
    "ubuntu1804": {
        "name": "Ubuntu 18.04, OpenJDK 11",
        "emoji-name": ":ubuntu: 18.04 (OpenJDK 11)",
        "downstream-root": "/var/lib/buildkite-agent/builds/${BUILDKITE_AGENT_NAME}/${BUILDKITE_ORGANIZATION_SLUG}-downstream-projects",
        "publish_binary": ["ubuntu1804"],
        "docker-image": f"gcr.io/{CLOUD_PROJECT}/ubuntu1804:java11",
        "python": "python3.6",
    },
    "ubuntu1804_nojava": {
        "name": "Ubuntu 18.04, no JDK",
        "emoji-name": ":ubuntu: 18.04 (no JDK)",
        "downstream-root": "/var/lib/buildkite-agent/builds/${BUILDKITE_AGENT_NAME}/${BUILDKITE_ORGANIZATION_SLUG}-downstream-projects",
        "publish_binary": [],
        "docker-image": f"gcr.io/{CLOUD_PROJECT}/ubuntu1804:nojava",
        "python": "python3.6",
    },
    "macos": {
        "name": "macOS, OpenJDK 8",
        "emoji-name": ":darwin: (OpenJDK 8)",
        "downstream-root": "/Users/buildkite/builds/${BUILDKITE_AGENT_NAME}/${BUILDKITE_ORGANIZATION_SLUG}-downstream-projects",
        "publish_binary": ["macos"],
        "queue": "macos",
        "python": "python3.7",
    },
    "windows": {
        "name": "Windows, OpenJDK 8",
        "emoji-name": ":windows: (OpenJDK 8)",
        "downstream-root": "d:/b/${BUILDKITE_AGENT_NAME}/${BUILDKITE_ORGANIZATION_SLUG}-downstream-projects",
        "publish_binary": ["windows"],
        "queue": "windows",
        "python": "python.exe",
    },
    "rbe_ubuntu1604": {
        "name": "RBE (Ubuntu 16.04, OpenJDK 8)",
        "emoji-name": "RBE (:ubuntu: 16.04, OpenJDK 8)",
        "downstream-root": "/var/lib/buildkite-agent/builds/${BUILDKITE_AGENT_NAME}/${BUILDKITE_ORGANIZATION_SLUG}-downstream-projects",
        "publish_binary": [],
        "docker-image": f"gcr.io/{CLOUD_PROJECT}/ubuntu1604:java8",
        "python": "python3.6",
    },
}

BUILDIFIER_DOCKER_IMAGE = "gcr.io/bazel-public/buildifier"

# The platform used for various steps (e.g. stuff that formerly ran on the "pipeline" workers).
DEFAULT_PLATFORM = "ubuntu1804"

DEFAULT_XCODE_VERSION = "10.2.1"
XCODE_VERSION_REGEX = re.compile(r"^\d+\.\d+(\.\d+)?$")

BUILD_LABEL_PATTERN = re.compile(r"^Build label: (\S+)$", re.MULTILINE)

BUILDIFIER_VERSION_ENV_VAR = "BUILDIFIER_VERSION"

BUILDIFIER_WARNINGS_ENV_VAR = "BUILDIFIER_WARNINGS"

BUILDIFIER_STEP_NAME = "Buildifier"

SKIP_TASKS_ENV_VAR = "CI_SKIP_TASKS"

CONFIG_FILE_EXTENSIONS = {".yml", ".yaml"}


class BuildkiteException(Exception):
    """
    Raised whenever something goes wrong and we should exit with an error.
    """

    pass


def eprint(*args, **kwargs):
    """
    Print to stderr and flush (just in case).
    """
    print(*args, flush=True, file=sys.stderr, **kwargs)


def is_windows():
    return os.name == "nt"


def gsutil_command():
    return "gsutil.cmd" if is_windows() else "gsutil"


def fetch_configs(http_url, file_config):
    """
    If specified fetches the build configuration from file_config or http_url, else tries to
    read it from .bazelci/presubmit.yml.
    Returns the json configuration as a python data structure.
    """
    if file_config is not None and http_url is not None:
        raise BuildkiteException("file_config and http_url cannot be set at the same time")

    return load_config(http_url, file_config)


def load_config(http_url, file_config, allow_imports=True):
    if http_url:
        config = load_remote_yaml_file(http_url)
    else:
        file_config = file_config or ".bazelci/presubmit.yml"
        with open(file_config, "r") as fd:
            config = yaml.safe_load(fd)

    # Legacy mode means that there is exactly one task per platform (e.g. ubuntu1604_nojdk),
    # which means that we can get away with using the platform name as task ID.
    # No other updates are needed since get_platform_for_task() falls back to using the
    # task ID as platform if there is no explicit "platforms" field.
    if "platforms" in config:
        config["tasks"] = config.pop("platforms")

    if "tasks" not in config:
        config["tasks"] = {}

    imports = config.pop("imports", None)
    if imports:
        if not allow_imports:
            raise BuildkiteException("Nested imports are not allowed")

        for i in imports:
            imported_tasks = load_imported_tasks(i, http_url, file_config)
            config["tasks"].update(imported_tasks)

    return config


def load_remote_yaml_file(http_url):
    with urllib.request.urlopen(http_url) as resp:
        reader = codecs.getreader("utf-8")
        return yaml.safe_load(reader(resp))


def load_imported_tasks(import_name, http_url, file_config):
    if "/" in import_name:
        raise BuildkiteException("Invalid import '%s'" % import_name)

    old_path = http_url or file_config
    new_path = "%s%s" % (old_path[: old_path.rfind("/") + 1], import_name)
    if http_url:
        http_url = new_path
    else:
        file_config = new_path

    imported_config = load_config(http_url=http_url, file_config=file_config, allow_imports=False)

    namespace = import_name.partition(".")[0]
    tasks = {}
    for task_name, task_config in imported_config["tasks"].items():
        if "platform" not in task_config:
            task_config["platform"] = task_name
        for field in ["name", "working_directory"]:
            if field not in task_config:
                task_config[field] = namespace

        tasks["%s_%s" % (namespace, task_name)] = task_config

    return tasks


def print_collapsed_group(name):
    eprint("\n\n--- {0}\n\n".format(name))


def print_expanded_group(name):
    eprint("\n\n+++ {0}\n\n".format(name))


def execute_commands(
    task_config,
    platform,
    monitor_flaky_tests,
    bazel_version=None,
):
    tmpdir = tempfile.mkdtemp()
    try:
        if platform == "macos":
            activate_xcode(task_config)

        # If the CI worker runs Bazelisk, we need to forward all required env variables to the test.
        # Otherwise any integration test that invokes Bazel (=Bazelisk in this case) will fail.
        test_env_vars = ["LocalAppData"] if platform == "windows" else ["HOME"]

        bazel_binary = "bazel"
        if bazel_version:
            # This will only work if the bazel binary in $PATH is actually a bazelisk binary
            # (https://github.com/bazelbuild/bazelisk).
            os.environ["USE_BAZEL_VERSION"] = bazel_version
            test_env_vars.append("USE_BAZEL_VERSION")

        for key, value in task_config.get("environment", {}).items():
            # We have to explicitly convert the value to a string, because sometimes YAML tries to
            # be smart and converts strings like "true" and "false" to booleans.
            os.environ[key] = str(value)

        # Allow the config to override the current working directory.
        required_prefix = os.getcwd()
        requested_working_dir = os.path.abspath(task_config.get("working_directory", ""))
        if os.path.commonpath([required_prefix, requested_working_dir]) != required_prefix:
            raise BuildkiteException("working_directory refers to a path outside the workspace")
        os.chdir(requested_working_dir)

        if platform == "windows":
            execute_batch_commands(task_config.get("batch_commands", None))
        else:
            execute_shell_commands(task_config.get("shell_commands", None))

        bazel_version = print_bazel_version_info(bazel_binary, platform)

        print_environment_variables_info()

        execute_bazel_run(
            bazel_binary, platform, task_config.get("run_targets", None)
        )

        build_targets, test_targets = calculate_targets(
            task_config, platform, bazel_binary
        )

        include_json_profile = task_config.get("include_json_profile", [])

        if build_targets:
            json_profile_flags = []
            include_json_profile_build = "build" in include_json_profile
            json_profile_out_build = None
            if include_json_profile_build:
                json_profile_out_build = os.path.join(tmpdir, "build.profile.gz")
                json_profile_flags = get_json_profile_flags(json_profile_out_build)

            build_flags = task_config.get("build_flags") or []
            try:
                execute_bazel_build(
                    bazel_version,
                    bazel_binary,
                    platform,
                    build_flags + json_profile_flags,
                    build_targets,
                )
            finally:
                if include_json_profile_build:
                    upload_json_profile(json_profile_out_build, tmpdir)

        if test_targets:
            json_profile_flags = []
            include_json_profile_test = "test" in include_json_profile
            json_profile_out_test = None
            if include_json_profile_test:
                json_profile_out_test = os.path.join(tmpdir, "test.profile.gz")
                json_profile_flags = get_json_profile_flags(json_profile_out_test)

            test_flags = task_config.get("test_flags") or []
            test_flags += json_profile_flags
            if test_env_vars:
                test_flags += ["--test_env={}".format(v) for v in test_env_vars]

            if not is_windows():
                # On platforms that support sandboxing (Linux, MacOS) we have
                # to allow access to Bazelisk's cache directory.
                # However, the flag requires the directory to exist,
                # so we create it here in order to not crash when a test
                # does not invoke Bazelisk.
                bazelisk_cache_dir = get_bazelisk_cache_directory(platform)
                os.makedirs(bazelisk_cache_dir, mode=0o755, exist_ok=True)
                test_flags.append("--sandbox_writable_path={}".format(bazelisk_cache_dir))

            test_bep_file = os.path.join(tmpdir, "test_bep.json")
            stop_request = threading.Event()
            upload_thread = threading.Thread(
                target=upload_test_logs_from_bep, args=(test_bep_file, tmpdir, stop_request)
            )
            try:
                upload_thread.start()
                try:
                    execute_bazel_test(
                        bazel_version,
                        bazel_binary,
                        platform,
                        test_flags,
                        test_targets,
                        test_bep_file,
                        monitor_flaky_tests,
                    )
                    if monitor_flaky_tests:
                        upload_bep_logs_for_flaky_tests(test_bep_file)
                finally:
                    if include_json_profile_test:
                        upload_json_profile(json_profile_out_test, tmpdir)
            finally:
                stop_request.set()
                upload_thread.join()
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir)


def activate_xcode(task_config):
    # Get the Xcode version from the config.
    xcode_version = task_config.get("xcode_version", DEFAULT_XCODE_VERSION)
    print_collapsed_group("Activating Xcode {}...".format(xcode_version))

    # Ensure it's a valid version number.
    if not isinstance(xcode_version, str):
        raise BuildkiteException(
            "Version number '{}' is not a string. Did you forget to put it in quotes?".format(
                xcode_version
            )
        )
    if not XCODE_VERSION_REGEX.match(xcode_version):
        raise BuildkiteException(
            "Invalid Xcode version format '{}', must match the format X.Y[.Z].".format(
                xcode_version
            )
        )

    # Check that the selected Xcode version is actually installed on the host.
    xcode_path = "/Applications/Xcode{}.app".format(xcode_version)
    if not os.path.exists(xcode_path):
        raise BuildkiteException("Xcode not found at '{}'.".format(xcode_path))

    # Now activate the specified Xcode version and let it install its required components.
    # The CI machines have a sudoers config that allows the 'buildkite' user to run exactly
    # these two commands, so don't change them without also modifying the file there.
    execute_command(["/usr/bin/sudo", "/usr/bin/xcode-select", "--switch", xcode_path])
    execute_command(["/usr/bin/sudo", "/usr/bin/xcodebuild", "-runFirstLaunch"])


def get_bazelisk_cache_directory(platform):
    # The path relies on the behavior of Go's os.UserCacheDir()
    # and of the Go version of Bazelisk.
    cache_dir = "Library/Caches" if platform == "macos" else ".cache"
    return os.path.join(os.environ.get("HOME"), cache_dir, "bazelisk")


def has_flaky_tests(bep_file):
    return len(test_logs_for_status(bep_file, status=["FLAKY"])) > 0


def print_bazel_version_info(bazel_binary, platform):
    print_collapsed_group(":information_source: Bazel Info")
    version_output = execute_command_and_get_output(
        [bazel_binary]
        + common_startup_flags(platform)
        + ["--nomaster_bazelrc", "--bazelrc=/dev/null", "version"]
    )
    execute_command(
        [bazel_binary]
        + common_startup_flags(platform)
        + ["--nomaster_bazelrc", "--bazelrc=/dev/null", "info"]
    )

    match = BUILD_LABEL_PATTERN.search(version_output)
    return match.group(1) if match else "unreleased binary"


def print_environment_variables_info():
    print_collapsed_group(":information_source: Environment Variables")
    for key, value in os.environ.items():
        eprint("%s=(%s)" % (key, value))


def execute_batch_commands(commands):
    if not commands:
        return
    print_collapsed_group(":batch: Setup (Batch Commands)")
    batch_commands = "&".join(commands)
    return subprocess.run(batch_commands, shell=True, check=True, env=os.environ).returncode


def execute_shell_commands(commands):
    if not commands:
        return
    print_collapsed_group(":bash: Setup (Shell Commands)")
    shell_command = "\n".join(commands)
    execute_command([shell_command], shell=True)


def handle_bazel_failure(exception, action):
    raise BuildkiteException("bazel {0} failed with exit code {1}".format(action, exception.returncode))


def execute_bazel_run(bazel_binary, platform, targets):
    if not targets:
        return
    print_collapsed_group("Setup (Run Targets)")
    for target in targets:
        try:
            execute_command(
                [bazel_binary]
                + common_startup_flags(platform)
                + ["run"]
                + common_build_flags(None, platform)
                + [target]
            )
        except subprocess.CalledProcessError as e:
            handle_bazel_failure(e, "run")


def remote_caching_flags(platform):
    # Only enable caching for untrusted and testing builds.
    if CLOUD_PROJECT not in ["bazel-untrusted"]:
        return []

    platform_cache_key = [BUILDKITE_ORG.encode("utf-8")]

    if platform == "macos":
        platform_cache_key += [
            # macOS version:
            subprocess.check_output(["/usr/bin/sw_vers", "-productVersion"]),
            # Path to Xcode:
            subprocess.check_output(["/usr/bin/xcode-select", "-p"]),
            # Xcode version:
            subprocess.check_output(["/usr/bin/xcodebuild", "-version"]),
        ]
        # Use a local cache server for our macOS machines.
        flags = ["--remote_cache=http://100.107.73.186"]
    else:
        platform_cache_key += [
            # Platform name:
            platform.encode("utf-8")
        ]
        # Use RBE for caching builds running on GCE.
        flags = [
            "--google_default_credentials",
            "--remote_cache=remotebuildexecution.googleapis.com",
            "--remote_instance_name=projects/{}/instances/default_instance".format(CLOUD_PROJECT),
            "--tls_enabled=true",
        ]

    platform_cache_digest = hashlib.sha256()
    for key in platform_cache_key:
        eprint("Adding to platform cache key: {}".format(key))
        platform_cache_digest.update(key)
        platform_cache_digest.update(b":")

    flags += [
        "--remote_timeout=60",
        "--remote_max_connections=200",
        '--remote_default_platform_properties=properties:{name:"cache-silo-key" value:"%s"}'
        % platform_cache_digest.hexdigest(),
    ]

    return flags


def remote_enabled(flags):
    # Detect if the project configuration enabled its own remote caching / execution.
    remote_flags = ["--remote_executor", "--remote_cache", "--remote_http_cache"]
    for flag in flags:
        for remote_flag in remote_flags:
            if flag.startswith(remote_flag):
                return True
    return False


def concurrent_jobs(platform):
    return "75" if platform.startswith("rbe_") else str(multiprocessing.cpu_count())


def concurrent_test_jobs(platform):
    if platform.startswith("rbe_"):
        return "75"
    elif platform == "windows":
        return "8"
    elif platform == "macos":
        return "8"
    return "12"


def common_startup_flags(platform):
    return ["--output_user_root=D:/b"] if platform == "windows" else []


def common_build_flags(bep_file, platform):
    flags = [
        "--show_progress_rate_limit=5",
        "--curses=yes",
        "--color=yes",
        "--terminal_columns=143",
        "--show_timestamps",
        "--verbose_failures",
        "--keep_going",
        "--jobs=" + concurrent_jobs(platform),
        "--announce_rc",
        "--experimental_multi_threaded_digest",
        "--experimental_repository_cache_hardlinks",
        # Some projects set --disk_cache in their project-specific bazelrc, which we never want on
        # CI, so let's just disable it explicitly.
        "--disk_cache=",
    ]

    if platform == "windows":
        pass
    elif platform == "macos":
        flags += [
            "--sandbox_writable_path=/var/tmp/_bazel_buildkite/cache/repos/v1",
            "--test_env=REPOSITORY_CACHE=/var/tmp/_bazel_buildkite/cache/repos/v1",
        ]
    else:
        flags += ["--sandbox_tmpfs_path=/tmp"]

    if bep_file:
        flags += [
            "--experimental_build_event_json_file_path_conversion=false",
            "--build_event_json_file=" + bep_file,
        ]

    return flags


def rbe_flags(original_flags, accept_cached):
    # Enable remote execution via RBE.
    flags = [
        "--remote_executor=remotebuildexecution.googleapis.com",
        "--remote_instance_name=projects/bazel-untrusted/instances/default_instance",
        "--remote_timeout=3600",
        # TODO(pcloudy): Remove this flag after upgrading Bazel to 0.27.0
        "--incompatible_list_based_execution_strategy_selection",
        "--experimental_strict_action_env",
        "--tls_enabled=true",
        "--google_default_credentials",
    ]

    # Enable BES / Build Results reporting.
    flags += [
        "--bes_backend=buildeventservice.googleapis.com",
        "--bes_timeout=360s",
        "--project_id=bazel-untrusted",
    ]

    if not accept_cached:
        flags += ["--noremote_accept_cached"]

    # Adapted from https://github.com/bazelbuild/bazel-toolchains/blob/master/bazelrc/.bazelrc
    flags += [
        # These should NOT longer need to be modified.
        # All that is needed is updating the @bazel_toolchains repo pin
        # in projects' WORKSPACE files.
        #
        # Toolchain related flags to append at the end of your .bazelrc file.
        "--host_javabase=@buildkite_config//java:jdk",
        "--javabase=@buildkite_config//java:jdk",
        "--host_java_toolchain=@bazel_tools//tools/jdk:toolchain_hostjdk8",
        "--java_toolchain=@bazel_tools//tools/jdk:toolchain_hostjdk8",
        "--crosstool_top=@buildkite_config//cc:toolchain",
        "--action_env=BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN=1",
    ]

    # Platform flags:
    # The toolchain container used for execution is defined in the target indicated
    # by "extra_execution_platforms", "host_platform" and "platforms".
    # If you are using your own toolchain container, you need to create a platform
    # target with "constraint_values" that allow for the toolchain specified with
    # "extra_toolchains" to be selected (given constraints defined in
    # "exec_compatible_with").
    # More about platforms: https://docs.bazel.build/versions/master/platforms.html
    # Don't add platform flags if they are specified already.
    platform_flags = {
        "--extra_toolchains": "@buildkite_config//config:cc-toolchain",
        "--extra_execution_platforms": "@buildkite_config//config:platform",
        "--host_platform": "@buildkite_config//config:platform",
        "--platforms": "@buildkite_config//config:platform",
    }
    for platform_flag, value in list(platform_flags.items()):
        found = False
        for original_flag in original_flags:
            if original_flag.startswith(platform_flag):
                found = True
                break
        if not found:
            flags += [platform_flag + "=" + value]

    return flags


def compute_flags(platform, flags, bep_file, enable_remote_cache=False):
    aggregated_flags = common_build_flags(bep_file, platform)
    if not remote_enabled(flags):
        if platform.startswith("rbe_"):
            aggregated_flags += rbe_flags(flags, accept_cached=enable_remote_cache)
        elif enable_remote_cache:
            aggregated_flags += remote_caching_flags(platform)
    aggregated_flags += flags

    return aggregated_flags


def execute_bazel_build(
    bazel_version, bazel_binary, platform, flags, targets
):
    print_collapsed_group(":bazel: Computing flags for build step")
    aggregated_flags = compute_flags(
        platform,
        flags,
        None,
        enable_remote_cache=True,
    )

    print_expanded_group(":bazel: Build ({})".format(bazel_version))
    try:
        execute_command(
            [bazel_binary]
            + common_startup_flags(platform)
            + ["build"]
            + aggregated_flags
            + targets
        )
    except subprocess.CalledProcessError as e:
        handle_bazel_failure(e, "build")


def calculate_targets(task_config, platform, bazel_binary):
    build_targets = task_config.get("build_targets", [])
    test_targets = task_config.get("test_targets", [])

    shard_id = int(os.getenv("BUILDKITE_PARALLEL_JOB", "-1"))
    shard_count = int(os.getenv("BUILDKITE_PARALLEL_JOB_COUNT", "-1"))
    if shard_id > -1 and shard_count > -1:
        print_collapsed_group(
            ":female-detective: Calculating targets for shard {}/{}".format(
                shard_id + 1, shard_count
            )
        )
        expanded_test_targets = expand_test_target_patterns(bazel_binary, platform, test_targets)
        build_targets, test_targets = get_targets_for_shard(
            build_targets, expanded_test_targets, shard_id, shard_count
        )

    return build_targets, test_targets


def expand_test_target_patterns(bazel_binary, platform, test_targets):
    included_targets, excluded_targets = partition_test_targets(test_targets)
    excluded_string = (
        " except tests(set({}))".format(" ".join("'{}'".format(t) for t in excluded_targets))
        if excluded_targets
        else ""
    )

    eprint("Resolving test targets via bazel query")
    output = execute_command_and_get_output(
        [bazel_binary]
        + common_startup_flags(platform)
        + [
            "--nomaster_bazelrc",
            "--bazelrc=/dev/null",
            "query",
            "tests(set({})){}".format(
                " ".join("'{}'".format(t) for t in included_targets), excluded_string
            ),
        ],
        print_output=False,
    )
    return output.split("\n")


def partition_test_targets(test_targets):
    included_targets, excluded_targets = [], []
    for target in test_targets:
        if target == "--":
            continue
        elif target.startswith("-"):
            excluded_targets.append(target[1:])
        else:
            included_targets.append(target)

    return included_targets, excluded_targets


def get_targets_for_shard(build_targets, test_targets, shard_id, shard_count):
    # TODO(fweikert): implement a more sophisticated algorithm
    build_targets_for_this_shard = sorted(build_targets)[shard_id::shard_count]
    test_targets_for_this_shard = sorted(test_targets)[shard_id::shard_count]

    return build_targets_for_this_shard, test_targets_for_this_shard


def execute_bazel_test(
    bazel_version,
    bazel_binary,
    platform,
    flags,
    targets,
    bep_file,
    monitor_flaky_tests,
):
    aggregated_flags = [
        "--flaky_test_attempts=3",
        "--build_tests_only",
        "--local_test_jobs=" + concurrent_test_jobs(platform),
    ]
    # Don't enable remote caching if the user enabled remote execution / caching themselves
    # or flaky test monitoring is enabled, as remote caching makes tests look less flaky than
    # they are.
    print_collapsed_group(":bazel: Computing flags for test step")
    aggregated_flags += compute_flags(
        platform,
        flags,
        bep_file,
        enable_remote_cache=not monitor_flaky_tests,
    )

    print_expanded_group(":bazel: Test ({})".format(bazel_version))
    try:
        execute_command(
            [bazel_binary]
            + common_startup_flags(platform)
            + ["test"]
            + aggregated_flags
            + targets
        )
    except subprocess.CalledProcessError as e:
        handle_bazel_failure(e, "test")


def get_json_profile_flags(out_file):
    return [
        "--experimental_generate_json_trace_profile",
        "--experimental_profile_cpu_usage",
        "--experimental_json_trace_compression",
        "--profile={}".format(out_file),
    ]


def upload_bep_logs_for_flaky_tests(test_bep_file):
    if has_flaky_tests(test_bep_file):
        build_number = os.getenv("BUILDKITE_BUILD_NUMBER")
        pipeline_slug = os.getenv("BUILDKITE_PIPELINE_SLUG")
        execute_command(
            [
                gsutil_command(),
                "cp",
                test_bep_file,
                FLAKY_TESTS_BUCKET + pipeline_slug + "/" + build_number + ".json",
            ]
        )


def upload_test_logs_from_bep(bep_file, tmpdir, stop_request):
    uploaded_targets = set()
    while True:
        done = stop_request.isSet()
        if os.path.exists(bep_file):
            all_test_logs = test_logs_for_status(bep_file, status=["FAILED", "TIMEOUT", "FLAKY"])
            test_logs_to_upload = [
                (target, files) for target, files in all_test_logs if target not in uploaded_targets
            ]

            if test_logs_to_upload:
                files_to_upload = rename_test_logs_for_upload(test_logs_to_upload, tmpdir)
                cwd = os.getcwd()
                try:
                    os.chdir(tmpdir)
                    test_logs = [os.path.relpath(file, tmpdir) for file in files_to_upload]
                    test_logs = sorted(test_logs)
                    execute_command(["buildkite-agent", "artifact", "upload", ";".join(test_logs)])
                finally:
                    uploaded_targets.update([target for target, _ in test_logs_to_upload])
                    os.chdir(cwd)
        if done:
            break
        time.sleep(0.2)


def upload_json_profile(json_profile_path, tmpdir):
    if not os.path.exists(json_profile_path):
        return
    print_collapsed_group(":gcloud: Uploading JSON Profile")
    execute_command(["buildkite-agent", "artifact", "upload", json_profile_path], cwd=tmpdir)


def rename_test_logs_for_upload(test_logs, tmpdir):
    # Rename the test.log files to the target that created them
    # so that it's easy to associate test.log and target.
    new_paths = []
    for label, files in test_logs:
        attempt = 0
        if len(files) > 1:
            attempt = 1
        for test_log in files:
            try:
                new_path = test_label_to_path(tmpdir, label, attempt)
                os.makedirs(os.path.dirname(new_path), exist_ok=True)
                copyfile(test_log, new_path)
                new_paths.append(new_path)
                attempt += 1
            except IOError as err:
                # Log error and ignore.
                eprint(err)
    return new_paths


def test_label_to_path(tmpdir, label, attempt):
    # remove leading //
    path = label[2:]
    path = path.replace("/", os.sep)
    path = path.replace(":", os.sep)
    if attempt == 0:
        path = os.path.join(path, "test.log")
    else:
        path = os.path.join(path, "attempt_" + str(attempt) + ".log")
    return os.path.join(tmpdir, path)


def test_logs_for_status(bep_file, status):
    targets = []
    with open(bep_file, encoding="utf-8") as f:
        raw_data = f.read()
    decoder = json.JSONDecoder()

    pos = 0
    while pos < len(raw_data):
        try:
            bep_obj, size = decoder.raw_decode(raw_data[pos:])
        except ValueError as e:
            eprint("JSON decoding error: " + str(e))
            return targets
        if "testSummary" in bep_obj:
            test_target = bep_obj["id"]["testSummary"]["label"]
            test_status = bep_obj["testSummary"]["overallStatus"]
            if test_status in status:
                outputs = bep_obj["testSummary"]["failed"]
                test_logs = []
                for output in outputs:
                    test_logs.append(url2pathname(urlparse(output["uri"]).path))
                targets.append((test_target, test_logs))
        pos += size + 1
    return targets


def execute_command_and_get_output(args, shell=False, fail_if_nonzero=True, print_output=True):
    eprint(" ".join(args))
    process = subprocess.run(
        args,
        shell=shell,
        check=fail_if_nonzero,
        env=os.environ,
        stdout=subprocess.PIPE,
        errors="replace",
        universal_newlines=True,
    )
    if print_output:
        eprint(process.stdout)

    return process.stdout


def execute_command(args, shell=False, fail_if_nonzero=True, cwd=None):
    eprint(" ".join(args))
    return subprocess.run(
        args, shell=shell, check=fail_if_nonzero, env=os.environ, cwd=cwd
    ).returncode


def create_step(label, commands, platform, shards=1):
    if "docker-image" in PLATFORMS[platform]:
        step = create_docker_step(
            label, image=PLATFORMS[platform]["docker-image"], commands=commands
        )
    else:
        step = {
            "label": label,
            "command": commands,
            "agents": {"queue": PLATFORMS[platform]["queue"]},
        }

    if shards > 1:
        step["label"] += " (shard %n)"
        step["parallelism"] = shards

    # Enforce a global 8 hour job timeout.
    step["timeout_in_minutes"] = 8 * 60

    # Automatically retry when an agent got lost (usually due to an infra flake).
    step["retry"] = {
        "automatic": [
            {"exit_status": -1, "limit": 3},  # Buildkite internal "agent lost" exit code
            {"exit_status": 137, "limit": 3},  # SIGKILL
            {"exit_status": 143, "limit": 3},  # SIGTERM
        ]
    }

    return step


def create_docker_step(label, image, commands=None, additional_env_vars=None):
    env = ["ANDROID_HOME", "ANDROID_NDK_HOME", "BUILDKITE_ARTIFACT_UPLOAD_DESTINATION"]
    if additional_env_vars:
        env += ["{}={}".format(k, v) for k, v in additional_env_vars.items()]

    step = {
        "label": label,
        "command": commands,
        "agents": {"queue": "default"},
        "plugins": {
            "docker#v3.2.0": {
                "always-pull": True,
                "environment": env,
                "image": image,
                "network": "host",
                "privileged": True,
                "propagate-environment": True,
                "propagate-uid-gid": True,
                "volumes": [
                    "/etc/group:/etc/group:ro",
                    "/etc/passwd:/etc/passwd:ro",
                    "/opt:/opt:ro",
                    "/var/lib/buildkite-agent:/var/lib/buildkite-agent",
                    "/var/lib/gitmirrors:/var/lib/gitmirrors:ro",
                    "/var/run/docker.sock:/var/run/docker.sock",
                ],
            }
        },
    }
    if not step["command"]:
        del step["command"]
    return step


def print_project_pipeline(
    configs,
    http_config,
    file_config,
    monitor_flaky_tests,
):
    task_configs = configs.get("tasks", None)
    if not task_configs:
        raise BuildkiteException("Pipeline configuration is empty.")

    pipeline_steps = []
    task_configs = filter_tasks_that_should_be_skipped(task_configs, pipeline_steps)

    buildifier_config = configs.get("buildifier")
    # Skip Buildifier when we test downstream projects.
    if buildifier_config:
        buildifier_env_vars = {}
        if isinstance(buildifier_config, str):
            # Simple format:
            # ---
            # buildifier: latest
            buildifier_env_vars[BUILDIFIER_VERSION_ENV_VAR] = buildifier_config
        else:
            # Advanced format:
            # ---
            # buildifier:
            #   version: latest
            #   warnings: all

            def set_env_var(config_key, env_var_name):
                if config_key in buildifier_config:
                    buildifier_env_vars[env_var_name] = buildifier_config[config_key]

            set_env_var("version", BUILDIFIER_VERSION_ENV_VAR)
            set_env_var("warnings", BUILDIFIER_WARNINGS_ENV_VAR)

        if not buildifier_env_vars:
            raise BuildkiteException(
                'Invalid buildifier configuration entry "{}"'.format(buildifier_config)
            )

        pipeline_steps.append(
            create_docker_step(
                BUILDIFIER_STEP_NAME,
                image=BUILDIFIER_DOCKER_IMAGE,
                additional_env_vars=buildifier_env_vars,
            )
        )

    for task, task_config in task_configs.items():
        shards = task_config.get("shards", "1")
        try:
            shards = int(shards)
        except ValueError:
            raise BuildkiteException("Task {} has invalid shard value '{}'".format(task, shards))

        step = runner_step(
            platform=get_platform_for_task(task, task_config),
            task=task,
            task_name=task_config.get("name"),
            http_config=http_config,
            file_config=file_config,
            monitor_flaky_tests=monitor_flaky_tests,
            shards=shards,
        )
        pipeline_steps.append(step)

    if "validate_config" in configs:
        pipeline_steps += create_config_validation_steps()

    print(yaml.dump({"steps": pipeline_steps}))


def get_platform_for_task(task, task_config):
    # Most pipeline configurations have exactly one task per platform, which makes it
    # convenient to use the platform name as task ID. Consequently, we use the
    # task ID as platform if there is no explicit "platform" field.
    return task_config.get("platform", task)


def create_config_validation_steps():
    output = execute_command_and_get_output(
        ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", os.getenv("BUILDKITE_COMMIT")]
    )
    config_files = [
        l
        for l in output.split("\n")
        if l.startswith(".bazelci/") and os.path.splitext(l)[1] in CONFIG_FILE_EXTENSIONS
    ]
    return [
        create_step(
            label=":cop: Validate {}".format(f),
            commands=[
                fetch_bazelcipy_command(),
                "{} bazelci.py project_pipeline --file_config={}".format(
                    PLATFORMS[DEFAULT_PLATFORM]["python"], f
                ),
            ],
            platform=DEFAULT_PLATFORM,
        )
        for f in config_files
    ]


def runner_step(
    platform,
    task,
    task_name=None,
    project_name=None,
    http_config=None,
    file_config=None,
    monitor_flaky_tests=False,
    shards=1,
):
    command = PLATFORMS[platform]["python"] + " bazelci.py runner --task=" + task
    if http_config:
        command += " --http_config=" + http_config
    if file_config:
        command += " --file_config=" + file_config
    if monitor_flaky_tests:
        command += " --monitor_flaky_tests"
    label = create_label(platform, project_name, task_name=task_name)
    return create_step(
        label=label, commands=[fetch_bazelcipy_command(), command], platform=platform, shards=shards
    )


def fetch_bazelcipy_command():
    return "curl -sS {0} -o bazelci.py".format(SCRIPT_URL)


def create_label(platform, project_name, task_name=None):
    platform_display_name = PLATFORMS[platform]["emoji-name"]

    platform_label = (
        "{0} on {1}".format(task_name, platform_display_name)
        if task_name
        else platform_display_name
    )

    if project_name:
        return "{0} ({1})".format(project_name, platform_label)
    else:
        return platform_label


def filter_tasks_that_should_be_skipped(task_configs, pipeline_steps):
    skip_tasks = get_skip_tasks()
    if not skip_tasks:
        return task_configs

    actually_skipped = []
    skip_tasks = set(skip_tasks)
    for task in list(task_configs.keys()):
        if task in skip_tasks:
            actually_skipped.append(task)
            del task_configs[task]
            skip_tasks.remove(task)

    if not task_configs:
        raise BuildkiteException(
            "Nothing to do since all tasks in the configuration should be skipped."
        )

    annotations = []
    if actually_skipped:
        annotations.append(
            ("info", "Skipping the following task(s): {}".format(", ".join(actually_skipped)))
        )

    if skip_tasks:
        annotations.append(
            (
                "warning",
                (
                    "The following tasks should have been skipped, "
                    "but were not part of the configuration: {}"
                ).format(", ".join(skip_tasks)),
            )
        )

    if annotations:
        print_skip_task_annotations(annotations, pipeline_steps)

    return task_configs


def get_skip_tasks():
    value = os.getenv(SKIP_TASKS_ENV_VAR, "")
    return [v for v in value.split(",") if v]


def print_skip_task_annotations(annotations, pipeline_steps):
    commands = [
        "buildkite-agent annotate --style={} '{}'  --context 'ctx-{}'".format(s, t, hash(t))
        for s, t in annotations
    ]
    pipeline_steps.append(
        create_step(
            label=":pipeline: Print information about skipped tasks",
            commands=commands,
            platform=DEFAULT_PLATFORM,
        )
    )


# This is so that multiline python strings are represented as YAML
# block strings.
def str_presenter(dumper, data):
    if len(data.splitlines()) > 1:  # check for multiline string
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    yaml.add_representer(str, str_presenter)

    parser = argparse.ArgumentParser(description="Bazel Continuous Integration Script")
    parser.add_argument("--script", type=str)

    subparsers = parser.add_subparsers(dest="subparsers_name")

    project_pipeline = subparsers.add_parser("project_pipeline")
    project_pipeline.add_argument("--file_config", type=str)
    project_pipeline.add_argument("--http_config", type=str)
    project_pipeline.add_argument("--monitor_flaky_tests", type=bool, nargs="?", const=True)

    runner = subparsers.add_parser("runner")
    runner.add_argument("--task", action="store", type=str, default="")
    runner.add_argument("--file_config", type=str)
    runner.add_argument("--http_config", type=str)
    runner.add_argument("--monitor_flaky_tests", type=bool, nargs="?", const=True)

    args = parser.parse_args(argv)

    try:
        if args.subparsers_name == "project_pipeline":
            configs = fetch_configs(args.http_config, args.file_config)
            print_project_pipeline(
                configs=configs,
                http_config=args.http_config,
                file_config=args.file_config,
                monitor_flaky_tests=args.monitor_flaky_tests,
            )
        elif args.subparsers_name == "runner":
            configs = fetch_configs(args.http_config, args.file_config)
            tasks = configs.get("tasks", {})
            task_config = tasks.get(args.task)
            if not task_config:
                raise BuildkiteException(
                    "No such task '{}' in configuration. Available: {}".format(
                        args.task, ", ".join(tasks)
                    )
                )

            platform = get_platform_for_task(args.task, task_config)

            execute_commands(
                task_config=task_config,
                platform=platform,
                monitor_flaky_tests=args.monitor_flaky_tests,
                bazel_version=task_config.get("bazel") or configs.get("bazel"),
            )
        else:
            parser.print_help()
            return 2
    except BuildkiteException as e:
        eprint(str(e))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
