import os
import hmac
import hashlib
import json

import redis
from fastapi import FastAPI, Request, HTTPException
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = FastAPI()

# =====================================================================
# ENVIRONMENT VARIABLES
# =====================================================================

WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")

# =====================================================================
# REDIS CONNECTION
# =====================================================================

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")

redis_client = redis.Redis(
    host=REDIS_HOST,
    port=6379,
    db=0,
    socket_timeout=5
)

# =====================================================================
# GITHUB WEBHOOK SIGNATURE VERIFICATION
# =====================================================================

def verify_signature(payload_body: bytes, signature_header: str):
    """Verify that the payload came from GitHub."""

    if not signature_header:
        raise HTTPException(
            status_code=403,
            detail="Missing signature header"
        )

    hash_object = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        msg=payload_body,
        digestmod=hashlib.sha256
    )

    expected_signature = "sha256=" + hash_object.hexdigest()

    if not hmac.compare_digest(
        expected_signature,
        signature_header
    ):
        raise HTTPException(
            status_code=403,
            detail="Invalid signature"
        )


# =====================================================================
# ROOT ENDPOINT
# =====================================================================

@app.get("/")
def read_root():
    return {
        "status": "PatchIQ-iA is Alivee!"
    }


# =====================================================================
# GITHUB WEBHOOK
# =====================================================================

@app.post("/webhook")
async def handle_webhook(request: Request):

    # ---------------------------------------------------------------
    # 1. Read webhook
    # ---------------------------------------------------------------

    payload_body = await request.body()

    signature_header = request.headers.get(
        "X-Hub-Signature-256"
    )

    # ---------------------------------------------------------------
    # 2. Verify GitHub signature
    # ---------------------------------------------------------------

    verify_signature(
        payload_body,
        signature_header
    )

    # ---------------------------------------------------------------
    # 3. Parse payload
    # ---------------------------------------------------------------

    payload = await request.json()

    event = request.headers.get(
        "X-GitHub-Event"
    )

    action = payload.get(
        "action"
    )

    print(f"\n[DEBUG] Event Received: {event}")
    print(f"[DEBUG] Action Received: {action}")

    # ---------------------------------------------------------------
    # 4. Only process Pull Request events
    # ---------------------------------------------------------------

    if event == "pull_request":

        installation_id = payload["installation"]["id"]

        repo_full_name = payload["repository"]["full_name"]

        pr_number = payload["number"]

        print(
            f"[DEBUG] Queueing PR #{pr_number} "
            f"in {repo_full_name}..."
        )

        # -----------------------------------------------------------
        # 5. Create Redis job
        # -----------------------------------------------------------

        job = {
            "installation_id": installation_id,
            "repo_full_name": repo_full_name,
            "pr_number": pr_number
        }

        # Convert Python dictionary → JSON
        job_json = json.dumps(job)

        # -----------------------------------------------------------
        # 6. Push job into Redis
        # -----------------------------------------------------------

        redis_client.lpush(
            "patchiq_jobs",
            job_json
        )

        print(
            f"✅ PR #{pr_number} successfully queued!"
        )

        return {
            "status": "PR queued successfully",
            "pr_number": pr_number,
            "repository": repo_full_name
        }

    # ---------------------------------------------------------------
    # 7. Ignore non-PR events
    # ---------------------------------------------------------------

    print(
        f"[DEBUG] Ignoring non-PR event: {event}"
    )

    return {
        "status": "Event ignored"
    }