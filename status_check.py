import os
import subprocess

import pandas as pd
import requests
from dotenv import load_dotenv

load_dotenv()

# Configured via .env so this can point at a remote server without code
# changes. ES_USER/ES_PASSWORD are optional (basic auth) for a secured
# remote Elasticsearch - never hardcode credentials, only read from .env.
#
#   ES_HOST=http://remote-elastic-host:9200
#   ES_INDEX=logstash-*
#   ES_USER=...
#   ES_PASSWORD=...
#   TPOT_NAME_FILTER=tpot
#   DOCKER_HOST=tcp://remote-docker-host:2375   (docker CLI's own standard
#       env var - not read explicitly here; load_dotenv() puts it in
#       os.environ and the docker subprocess below inherits it automatically)
# `or` (not a .get default): empty placeholders copied from .env.example must
# fall back too - an empty TPOT_NAME_FILTER would otherwise match every container.
ES_HOST = (os.environ.get("ES_HOST") or "http://localhost:9200").rstrip("/")
ES_INDEX = os.environ.get("ES_INDEX") or "logstash-*"
ES_USER = os.environ.get("ES_USER")
ES_PASSWORD = os.environ.get("ES_PASSWORD")
TPOT_NAME_FILTER = os.environ.get("TPOT_NAME_FILTER") or "tpot"
ES_AUTH = (ES_USER, ES_PASSWORD) if ES_USER and ES_PASSWORD else None


def check_docker_containers():
    # Counts how many T-Pot containers are running.
    # Returns (running_count, total_count, error_message).
    # Uses the `docker ps` command, so no extra Python package is needed.
    try:
        result = subprocess.run(
            ["docker", "ps", "-a", "--filter", f"name={TPOT_NAME_FILTER}", "--format", "{{.State}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except FileNotFoundError:
        return 0, 0, "Docker CLI not found (not installed or not on PATH)."
    except subprocess.TimeoutExpired:
        return 0, 0, "Docker command timed out."

    if result.returncode != 0:
        error = result.stderr.strip() or "Could not reach the Docker daemon (possible permission issue)."
        return 0, 0, error

    states = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    total_count = len(states)
    running_count = sum(1 for state in states if state == "running")
    return running_count, total_count, None


def check_data_freshness():
    # Checks how long ago the last event arrived in Elasticsearch.
    # Returns (seconds_since_last_event, error_message).
    # Only fetches the newest event, not the whole index.
    query = {"size": 1, "sort": [{"@timestamp": {"order": "desc"}}]}
    try:
        response = requests.get(f"{ES_HOST}/{ES_INDEX}/_search", json=query, auth=ES_AUTH, timeout=3)
        response.raise_for_status()
        hits = response.json().get("hits", {}).get("hits", [])
    except requests.exceptions.ConnectionError:
        return None, "Elasticsearch unreachable (connection refused)."
    except requests.exceptions.Timeout:
        return None, "Elasticsearch timed out."
    except Exception:
        return None, "Elasticsearch query failed."

    if not hits:
        return None, "No events recorded yet."

    last_timestamp = pd.to_datetime(hits[0]["_source"]["@timestamp"])
    seconds_ago = (pd.Timestamp.now(tz="UTC") - last_timestamp).total_seconds()
    return seconds_ago, None


def _format_seconds_ago(seconds_ago):
    if seconds_ago < 60:
        return f"last event {int(seconds_ago)} sec ago"
    if seconds_ago < 3600:
        return f"last event {int(seconds_ago // 60)} min ago"
    return f"last event {int(seconds_ago // 3600)} hr ago"


def evaluate_system_status(freshness_threshold_minutes=5):
    # Combines the container check and the data check into one status:
    # - Live: containers are running and new data is coming in
    # - Degraded: only one of the two is OK
    # - Down: both were checked and both are bad
    # - Unknown: neither could be checked (this is not the same as Down)
    running_count, total_count, docker_error = check_docker_containers()
    seconds_ago, freshness_error = check_data_freshness()

    docker_unreachable = docker_error is not None
    freshness_unreachable = freshness_error is not None

    containers_healthy = not docker_unreachable and running_count > 0
    data_fresh = not freshness_unreachable and seconds_ago <= freshness_threshold_minutes * 60

    if docker_unreachable and freshness_unreachable:
        overall_status = "Unknown"
    elif containers_healthy and data_fresh:
        overall_status = "Live"
    elif containers_healthy or data_fresh:
        overall_status = "Degraded"
    else:
        overall_status = "Down"

    container_detail = docker_error if docker_error else f"{running_count}/{total_count} containers up"
    freshness_detail = freshness_error if freshness_error else _format_seconds_ago(seconds_ago)

    return {
        "overall_status": overall_status,
        "container_detail": container_detail,
        "freshness_detail": freshness_detail,
    }


if __name__ == "__main__":
    print(evaluate_system_status())
