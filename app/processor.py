import json
import os
import re

import ollama
from dotenv import load_dotenv
from github import GithubIntegration


# =====================================================================
# CONFIGURATION
# =====================================================================

load_dotenv()

APP_ID = os.getenv("GITHUB_APP_ID")
PRIVATE_KEY_PATH = os.getenv("GITHUB_PRIVATE_KEY_PATH")

# Switched back to DeepSeek for speed. The candidate-detection + evidence
# validation layer below is what actually prevents hallucinated findings
# from reaching GitHub, independent of which model is used — so DeepSeek's
# earlier misclassification problems (e.g. calling pickle.loads "SQL
# injection") are now structurally blocked rather than prompt-hoped-away.
OLLAMA_MODEL = "deepseek-coder:latest"


# =====================================================================
# GITHUB AUTHENTICATION
# =====================================================================

def get_github_client(installation_id: int):
    """Authenticate as the GitHub App."""

    if not APP_ID:
        raise ValueError("GITHUB_APP_ID is not set in .env")

    if not PRIVATE_KEY_PATH:
        raise ValueError(
            "GITHUB_PRIVATE_KEY_PATH is not set in .env"
        )

    if not os.path.exists(PRIVATE_KEY_PATH):
        raise FileNotFoundError(
            f"Private key file does not exist: {PRIVATE_KEY_PATH}"
        )

    with open(PRIVATE_KEY_PATH, "r") as key_file:
        private_key = key_file.read()

    print(
        f"[DEBUG AUTH] Key file loaded successfully "
        f"(Length: {len(private_key)} chars)"
    )

    git_integration = GithubIntegration(
        int(APP_ID),
        private_key
    )

    return git_integration.get_github_for_installation(
        installation_id
    )


# =====================================================================
# STATIC SECURITY ANALYSIS
# =====================================================================

def run_static_checks(file_patch: str, filename: str):
    """Run deterministic rule-based security checks."""

    findings = []

    secret_pattern = re.compile(
        r'(api[_-]?key|secret|password|token)'
        r'\s*=\s*[\'"][^\'"]{8,}[\'"]',
        re.IGNORECASE
    )

    if secret_pattern.search(file_patch):
        findings.append(
            f"Possible hardcoded secret detected in `{filename}`"
        )

    if re.search(r'\beval\s*\(', file_patch):
        findings.append(
            f"Unsafe `eval()` usage detected in `{filename}` "
            f"— may allow arbitrary code execution"
        )

    if re.search(
        r'(SELECT|INSERT|UPDATE|DELETE).*(\+|f["\'])',
        file_patch,
        re.IGNORECASE
    ):
        findings.append(
            f"Possible SQL injection risk in `{filename}` "
            f"— use parameterized queries"
        )

    return findings


# =====================================================================
# DIFF PARSING
# =====================================================================

def extract_added_lines(file_patch: str) -> str:
    """Extract only newly added source-code lines from a unified diff."""

    added_lines = []

    for line in file_patch.splitlines():

        if (
            line.startswith("+++")
            or line.startswith("---")
            or line.startswith("@@")
        ):
            continue

        if line.startswith("+"):
            added_lines.append(line[1:])

    return "\n".join(added_lines)


# =====================================================================
# AI CANDIDATE DETECTION
# =====================================================================

def detect_ai_candidates(added_code: str):
    """
    Determine which vulnerability categories are actually plausible from
    the code before asking the model to analyze anything. This is the
    first line of defense against hallucination — a category the model
    invents that isn't in this set gets rejected later regardless of how
    confidently the model states it.
    """

    candidates = set()

    if re.search(
        r'(api[_-]?key|secret|password|token)'
        r'\s*=\s*[\'"][^\'"]{8,}[\'"]',
        added_code,
        re.IGNORECASE
    ):
        candidates.add("HARDCODED_SECRETS")

    if re.search(r'\b(eval|exec)\s*\(', added_code):
        candidates.add("UNSAFE_EVAL_EXEC")

    if (
        re.search(r'\bos\.system\s*\(', added_code)
        or re.search(r'\bos\.popen\s*\(', added_code)
        or re.search(
            r'\bsubprocess\.(run|call|Popen|check_output)\s*\(',
            added_code
        )
        or re.search(r'\bshell\s*=\s*True', added_code)
    ):
        candidates.add("COMMAND_INJECTION")

    sql_present = re.search(
        r'\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b',
        added_code,
        re.IGNORECASE
    )

    sql_construction = (
        "+" in added_code
        or re.search(r'\bf[\'"]', added_code)
        or re.search(r'\.execute\s*\(', added_code, re.IGNORECASE)
    )

    if sql_present and sql_construction:
        candidates.add("SQL_INJECTION")

    file_access = re.search(
        r'\b(open|os\.path\.(join|isfile|exists)|Path)\s*\(',
        added_code
    )

    path_construction = (
        "+" in added_code
        or re.search(r'\bf[\'"]', added_code)
        or re.search(r'\.join\s*\(', added_code)
    )

    if file_access and path_construction:
        candidates.add("PATH_TRAVERSAL")

    if re.search(r'\bpickle\.(loads|load)\s*\(', added_code):
        candidates.add("INSECURE_DESERIALIZATION")

    if re.search(r'\byaml\.load\s*\(', added_code):
        candidates.add("UNSAFE_YAML_LOADING")

    return candidates


# =====================================================================
# AI RESPONSE PARSING
# =====================================================================

ALLOWED_VULNERABILITIES = {
    "HARDCODED_SECRETS",
    "UNSAFE_EVAL_EXEC",
    "COMMAND_INJECTION",
    "SQL_INJECTION",
    "PATH_TRAVERSAL",
    "INSECURE_DESERIALIZATION",
    "UNSAFE_YAML_LOADING",
}


def extract_json(text: str):
    """Extract JSON from the model response, handling ```json fences."""

    text = text.strip()

    if text.startswith("```"):
        text = re.sub(
            r"^```(?:json)?\s*",
            "",
            text,
            flags=re.IGNORECASE
        )
        text = re.sub(r"\s*```$", "", text)

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    end = text.rfind("}")

    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass

    return None


def _normalize_for_match(text: str) -> str:
    """Collapse all whitespace runs to single spaces. Faster/smaller models
    sometimes reformat spacing slightly while 'copying' a line of code —
    without this, a genuinely valid finding would get silently rejected
    just because of a formatting mismatch, turning it into a false negative."""
    return re.sub(r'\s+', ' ', text).strip()


def evidence_found_in_code(evidence: str, added_code: str) -> bool:
    """Check evidence against added_code both exactly and whitespace-
    normalized, so real findings survive minor reformatting by the model
    while fabricated evidence (not present in the code at all) still
    correctly gets rejected."""
    if evidence in added_code:
        return True

    return _normalize_for_match(evidence) in _normalize_for_match(added_code)


# =====================================================================
# AI RESPONSE VALIDATION
# =====================================================================

def validate_ai_result(
    raw_response: str,
    added_code: str,
    filename: str,
    candidates: set
):
    """
    Validate AI findings against allowed categories, plausible candidates,
    exact code evidence, and required fields. This is the layer that makes
    it safe to use a faster/less careful model like DeepSeek: the model's
    output is treated as a claim to verify, never as a fact to trust.
    """

    data = extract_json(raw_response)

    if not isinstance(data, dict):
        # Distinguish truncation (response doesn't end with a closing brace,
        # meaning it likely hit num_predict before finishing) from other
        # malformed-output cases, so this is diagnosable at a glance in logs.
        looks_truncated = not raw_response.rstrip().endswith("}")

        reason = (
            "response appears TRUNCATED (hit token limit before completing JSON)"
            if looks_truncated
            else "response is not valid JSON for another reason"
        )

        print(
            f"[AI WARNING] AI returned invalid JSON ({reason}). "
            f"Ignoring AI findings."
        )

        print(
            f"[AI WARNING] Response length was "
            f"{len(raw_response)} characters."
        )

        return []

    findings = data.get("findings", [])

    if not isinstance(findings, list):
        print("[AI WARNING] AI JSON does not contain a findings list.")
        return []

    validated = []

    for finding in findings:

        if not isinstance(finding, dict):
            continue

        vulnerability = str(
            finding.get("vulnerability", "")
        ).strip().upper()

        severity = str(
            finding.get("severity", "")
        ).strip().upper()

        evidence = str(
            finding.get("evidence", "")
        ).strip()

        reason = str(
            finding.get("reason", "")
        ).strip()

        recommendation = str(
            finding.get("recommendation", "")
        ).strip()

        if vulnerability not in ALLOWED_VULNERABILITIES:
            print(
                f"[AI VALIDATION] Rejected unsupported category: "
                f"{vulnerability}"
            )
            continue

        if vulnerability not in candidates:
            print(
                f"[AI VALIDATION] Rejected `{vulnerability}` — not a "
                f"detected candidate for this code."
            )
            continue

        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            print(
                f"[AI VALIDATION] Rejected invalid severity: "
                f"{severity}"
            )
            continue

        if not evidence:
            print(
                f"[AI VALIDATION] Rejected `{vulnerability}` — "
                f"evidence missing."
            )
            continue

        if not evidence_found_in_code(evidence, added_code):
            # Specifically flag the known failure mode where the model echoes
            # this file's own prompt-template placeholder text instead of
            # reasoning about the real code — distinct from a generic
            # hallucination so it's obvious at a glance in the logs.
            if (
                evidence.strip() == "os.system(command)"
                and vulnerability == "COMMAND_INJECTION"
            ):
                print(
                    f"[AI VALIDATION] Rejected `{vulnerability}` — this "
                    f"matches the prompt's own format example verbatim, "
                    f"meaning the model likely echoed the template instead "
                    f"of analyzing the real code. If this keeps happening, "
                    f"the example in the prompt may need to be varied further."
                )
            else:
                print(
                    f"[AI VALIDATION] Rejected `{vulnerability}` — "
                    f"evidence not found in added code (even after "
                    f"whitespace normalization):"
                )
                print(evidence)

            continue

        if not reason or not recommendation:
            print(
                f"[AI VALIDATION] Rejected `{vulnerability}` — "
                f"reason/recommendation missing."
            )
            continue

        duplicate = any(
            existing["vulnerability"] == vulnerability
            and existing["evidence"] == evidence
            for existing in validated
        )

        if duplicate:
            continue

        validated.append({
            "severity": severity,
            "vulnerability": vulnerability,
            "evidence": evidence,
            "reason": reason,
            "recommendation": recommendation,
        })

    return validated


# =====================================================================
# AI SECURITY ANALYSIS
# =====================================================================

def run_ai_analysis(file_patch: str, filename: str):
    """Analyze newly added code using DeepSeek through Ollama, restricted
    to vulnerability candidates that are actually plausible from the code."""

    print(
        f"[AI] Analyzing `{filename}` with {OLLAMA_MODEL}..."
    )

    added_code = extract_added_lines(file_patch)

    if not added_code.strip():
        print(
            f"[AI] No added code found in `{filename}`."
        )
        return []

    max_code_length = 12000
    truncated_code = added_code[:max_code_length]

    if len(added_code) > max_code_length:
        truncated_code += (
            "\n\n[Code truncated for AI analysis.]"
        )

    candidates = detect_ai_candidates(added_code)

    if not candidates:
        print(
            f"[AI] No supported vulnerability patterns detected in "
            f"`{filename}`. Skipping model call."
        )
        return []

    candidate_text = "\n".join(sorted(candidates))

    # Refined prompt: shorter, plain text (no emoji/decorative symbols),
    # explicit disambiguation rules for the exact confusions DeepSeek made
    # previously (pickle -> SQL, os.system -> file access).
    prompt = f"""You are the secondary security reviewer for PatchIQ-iA.

Analyze ONLY the newly added source code below.

A deterministic scanner has already identified these categories as plausible candidates for this code:
{candidate_text}

Decide which of these candidates are ACTUALLY present. Do not consider any category outside this list.

Rules:
1. Report only vulnerabilities directly supported by the code shown below.
2. Never invent or speculate about vulnerabilities.
3. Never report a category outside the candidate list above.
4. "evidence" must be an exact substring copied from the supplied source code, character for character.
5. "reason" must explain why that exact evidence creates the reported vulnerability, in one plain sentence.
6. "recommendation" must be one plain sentence with a concrete fix.
7. pickle.loads or pickle.load is INSECURE_DESERIALIZATION. It is never SQL_INJECTION.
8. yaml.load is UNSAFE_YAML_LOADING. It is never SQL_INJECTION.
9. os.system, os.popen, or subprocess with shell=True is COMMAND_INJECTION. It is never PATH_TRAVERSAL or file access related.
10. SQL_INJECTION requires an actual SQL query (SELECT/INSERT/UPDATE/DELETE) being built with string concatenation or an f-string. If no SQL query text exists anywhere in the code, do not report SQL_INJECTION under any circumstance.
11. PATH_TRAVERSAL requires a file or path operation built from unsanitized variable input.
12. Do not report the same evidence twice.
13. Do not create a "no vulnerabilities found" entry — just return an empty findings list.
14. If a candidate is not actually vulnerable in this code, omit it entirely.
15. Return ONLY raw JSON. No markdown, no code fences, no emoji, no extra commentary before or after the JSON.
16. The example below shows FORMAT ONLY, using a placeholder category that is not real. Never copy its category name, evidence, reason, or recommendation into your actual response. Every real finding you return must reference one of the candidate categories listed above and quote evidence that actually appears in the source code below.

JSON structure (format example only — placeholder values, not a real finding):
{{
"findings": [
    {{
    "severity": "HIGH or MEDIUM or LOW or CRITICAL",
    "vulnerability": "ONE_OF_THE_CANDIDATE_CATEGORIES_LISTED_ABOVE",
    "evidence": "the exact line of code copied from the SOURCE CODE section below",
    "reason": "one plain sentence explaining why that exact evidence is vulnerable",
    "recommendation": "one plain sentence with a concrete fix"
    }}
]
}}

If no candidate is actually vulnerable, return exactly:
{{
"findings": []
}}

Your entire response must be a single JSON object and nothing else. Do not write any analysis, explanation, or reasoning before the JSON. Do not use markdown code fences. The very first character of your response must be {{ and the very last character must be }}.

SOURCE CODE:
{truncated_code}"""

    try:
        response = ollama.chat(
            model=OLLAMA_MODEL,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            format="json",
            options={
                "temperature": 0.0,
                "num_predict": 900
            }
        )

        raw_response = response["message"]["content"].strip()

        print(
            f"\n[AI DEBUG] Raw response for `{filename}`:"
        )
        print(raw_response)

        validated = validate_ai_result(
            raw_response,
            added_code,
            filename,
            candidates
        )

        print(
            f"[AI DEBUG] Validated findings for `{filename}`: "
            f"{len(validated)}"
        )

        for finding in validated:
            print(
                f"[AI DEBUG] Accepted: "
                f"{finding['vulnerability']} -> "
                f"{finding['evidence']}"
            )

        return validated

    except Exception as e:
        print(
            f"[AI ERROR] Analysis failed for `{filename}`: {e}"
        )
        return []


# =====================================================================
# FULL PR PROCESSING PIPELINE
# =====================================================================

def process_pull_request(
    installation_id: int,
    repo_full_name: str,
    pr_number: int
):
    """Fetch PR, run static and AI analysis, and post one combined review."""

    print(
        f"\n[PROCESSOR] Starting review for PR "
        f"#{pr_number} in {repo_full_name}"
    )

    gh = get_github_client(installation_id)
    repo = gh.get_repo(repo_full_name)
    pr = repo.get_pull(pr_number)

    files = pr.get_files()

    static_findings = []
    ai_findings = []
    files_checked = 0

    for file in files:

        if file.status not in ["added", "modified"]:
            continue

        if not file.patch:
            continue

        files_checked += 1

        print(
            f"[PROCESSOR] Checking file: {file.filename}"
        )

        static_results = run_static_checks(
            file.patch,
            file.filename
        )

        static_findings.extend(static_results)

        ai_results = run_ai_analysis(
            file.patch,
            file.filename
        )

        for finding in ai_results:
            ai_findings.append({
                "filename": file.filename,
                "severity": finding["severity"],
                "vulnerability": finding["vulnerability"],
                "evidence": finding["evidence"],
                "reason": finding["reason"],
                "recommendation": finding["recommendation"],
            })

    comment_sections = [
        "## PatchIQ-iA Security Review"
    ]

    if files_checked == 0:
        comment_sections.append(
            "_No added or modified files with reviewable changes were found._"
        )

    else:
        if static_findings:
            comment_sections.append(
                "### Static Analysis Findings\n\n"
                + "\n".join(
                    f"- {finding}"
                    for finding in static_findings
                )
            )

        else:
            comment_sections.append(
                "### Static Analysis Findings\n\n"
                "No pattern-based issues detected."
            )

        if ai_findings:
            ai_section = [
                "### AI Security Analysis"
            ]

            for finding in ai_findings:
                ai_section.append(
                    f"\n**{finding['severity']} — "
                    f"{finding['vulnerability']}**"
                )

                ai_section.append(
                    f"\n**File:** `{finding['filename']}`"
                )

                ai_section.append(
                    f"\n**Evidence:** `{finding['evidence']}`"
                )

                ai_section.append(
                    f"\n**Reason:** {finding['reason']}"
                )

                ai_section.append(
                    f"\n**Recommendation:** "
                    f"{finding['recommendation']}\n"
                )

            comment_sections.append(
                "\n".join(ai_section)
            )

        else:
            comment_sections.append(
                "### AI Security Analysis\n\n"
                "No validated AI vulnerabilities found."
            )

    comment_body = "\n\n".join(comment_sections)

    print(
        f"[PROCESSOR] Posting review to PR #{pr_number}..."
    )

    pr.create_issue_comment(comment_body)

    print(
        f"[PROCESSOR] Review posted successfully "
        f"for PR #{pr_number}"
    )

    return True