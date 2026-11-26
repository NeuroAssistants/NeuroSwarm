"""Publish an explicit operator-visible task update using the enrolled host token."""
import argparse
import json
from client import SwarmEventClient


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("stage", choices=["plan", "work_started", "work_done", "decision", "blocker", "agent_message", "memory_saved"])
    for key in ("agent", "harness", "workspace", "summary"):
        p.add_argument("--" + key, required=True)
    p.add_argument("--task-id", default="", help="Stable task identifier shared by its stages")
    p.add_argument("--mission-id", default="", help="Mission shared by related tasks or agents")
    p.add_argument("--to-agent", default="", help="Recipient of this reported message")
    p.add_argument("--reason", default="", help="Brief explanation explicitly shared by the agent")
    p.add_argument("--method", default="")
    p.add_argument("--file", action="append", default=[])
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()
    if args.stage in ("decision", "blocker", "agent_message", "memory_saved") and not (args.task_id or args.mission_id):
        p.error("A task or mission identifier is required for this report")
    if args.stage == "agent_message" and not args.to_agent:
        p.error("--to-agent is required for a message")
    result = SwarmEventClient().emit(harness=args.harness, agent_name=args.agent,
        event_type=args.stage, message=args.summary, dry_run=args.dry_run,
        metadata={"workspace": args.workspace, "method": args.method, "files": args.file[:12],
                  "task_id": args.task_id, "mission_id": args.mission_id, "to_agent": args.to_agent, "reason": args.reason})
    if args.dry_run:
        print(json.dumps(result.payload, ensure_ascii=False, indent=2))
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
