"""Publish an explicit operator-visible task update using the enrolled host token."""
import argparse
import json
from client import SwarmEventClient


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("stage", choices=["plan", "work_started", "work_done"])
    for key in ("agent", "harness", "workspace", "summary"):
        p.add_argument("--" + key, required=True)
    p.add_argument("--task-id", default="", help="Stable task identifier shared by its stages")
    p.add_argument("--method", default="")
    p.add_argument("--file", action="append", default=[])
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()
    result = SwarmEventClient().emit(harness=args.harness, agent_name=args.agent,
        event_type=args.stage, message=args.summary, dry_run=args.dry_run,
        metadata={"workspace": args.workspace, "method": args.method, "files": args.file[:12],
                  "task_id": args.task_id})
    if args.dry_run:
        print(json.dumps(result.payload, ensure_ascii=False, indent=2))
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
