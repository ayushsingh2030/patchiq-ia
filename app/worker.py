import json
import os

import redis

from processor import process_pull_request

# =====================================================================
# REDIS CONNECTION
# =====================================================================

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")

redis_client = redis.Redis(
    host=REDIS_HOST,
    port=6379,
    db=0,
    socket_timeout=None
)


# =====================================================================
# START WORKER
# =====================================================================

print("PATCHIQ WORKER STARTING...")

try:
    redis_client.ping()
    print("REDIS CONNECTION: OK")
except redis.ConnectionError:
    print("REDIS CONNECTION: FAILED")
    raise


print("PATCHIQ WORKER: WAITING FOR JOBS...")


# =====================================================================
# JOB LOOP
# =====================================================================

while True:

    job = redis_client.blpop(
        "patchiq_jobs",
        timeout=0
    )

    if not job:
        continue

    try:
        # Redis returns bytes, so decode the job
        job_data = job[1].decode("utf-8")

        # Convert JSON string into Python dictionary
        job_data = json.loads(job_data)

        print(f"\n[WORKER] JOB RECEIVED: {job_data}")

        # Extract job information
        installation_id = job_data["installation_id"]
        repo_full_name = job_data["repo_full_name"]
        pr_number = job_data["pr_number"]

        print(
            f"[WORKER] Processing PR #{pr_number} "
            f"in {repo_full_name}..."
        )

        # Run the actual PatchIQ-iA PR processor
        process_pull_request(
            installation_id=installation_id,
            repo_full_name=repo_full_name,
            pr_number=pr_number
        )

        print(
            f"[WORKER] JOB COMPLETED: "
            f"PR #{pr_number} in {repo_full_name}"
        )

    except Exception as e:
        print(f"[WORKER ERROR] {e}")