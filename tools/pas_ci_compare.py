"""Compare PaS estimates between PR and main and post a comment if cost increased.

Expects `pr_estimate.json` and `main_estimate.json` in the working directory and
`GITHUB_TOKEN` and `GITHUB_REPOSITORY` and `GITHUB_REF` to be set in the environment.
"""
import json
import os
import sys
from urllib.request import Request, urlopen
from urllib.error import HTTPError


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def post_pr_comment(owner, repo, pr_number, body, token):
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
    data = json.dumps({"body": body}).encode("utf-8")
    req = Request(url, data=data, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json",
    })
    try:
        resp = urlopen(req)
        return resp.getcode()
    except HTTPError as e:
        print("Failed to post comment:", e.read().decode(), file=sys.stderr)
        return e.code
    except Exception as e:
        print("Failed to post comment:", e, file=sys.stderr)
        return 1


def main():
    pr = load_json("pr_estimate.json")
    main = load_json("main_estimate.json")

    pr_cost = pr.get("estimated_monthly_cost", 0)
    main_cost = main.get("estimated_monthly_cost", 0)
    threshold = float(os.getenv("PAS_INCREASE_THRESHOLD", "1.1"))

    if main_cost == 0:
        increase = float("inf") if pr_cost > 0 else 1.0
    else:
        increase = pr_cost / main_cost

    print(f"PR cost: {pr_cost}, main cost: {main_cost}, increase ratio: {increase:.2f}")

    if increase >= threshold:
        token = os.getenv("GITHUB_TOKEN")
        if not token:
            print("No GITHUB_TOKEN available - cannot post comment", file=sys.stderr)
            sys.exit(0)

        repo_full = os.getenv("GITHUB_REPOSITORY")
        if not repo_full:
            print("No GITHUB_REPOSITORY set", file=sys.stderr)
            sys.exit(1)
        owner, repo = repo_full.split("/")

        # Extract PR number from GITHUB_REF like refs/pull/<pr>/merge
        ref = os.getenv("GITHUB_REF", "")
        pr_number = None
        parts = ref.split("/")
        if len(parts) >= 3 and parts[1] == "pull":
            pr_number = parts[2]

        if not pr_number:
            print(f"Could not determine PR number from GITHUB_REF={ref}", file=sys.stderr)
            sys.exit(1)

        body = (
            f"PaS Guard: Estimated monthly cost changed from ${main_cost:.2f} to ${pr_cost:.2f} "
            f"(x{increase:.2f}). Please review any infra changes that increase costs."
        )

        code = post_pr_comment(owner, repo, pr_number, body, token)
        print("Posted comment, response code:", code)
    else:
        print("No significant cost increase detected")


if __name__ == "__main__":
    main()
