# See OpenBot assignments in NeuroSwarm

Open **Agent work → Collaboration by change** to see what the team is working on, who assigned each task, and the last result each agent delivered. A change appears when a root task has at least one child assignment in the same channel. The board follows the recorded parent IDs, so tasks with similar titles can still belong to different changes.

## Connect one channel

Set `SWARMCONTROL_OPENBOT_CHANNEL_ID` on the NeuroSwarm server to the exact ID of the OpenBot channel you want to share. Set `SWARMCONTROL_OPENBOT_CONFIG` if the directory containing `openbot.db` is somewhere other than `~/.config/OpenBot` for the account running the server. Leaving the channel ID empty turns the integration off.

Give the server read access to the database. If OpenBot uses SQLite write-ahead logging (WAL), the server also needs access to the accompanying SQLite files. In a container, mount the directory read-only so the reader sees the same database and WAL files.

Only the original NeuroSwarm organization (ID `1`) can see this channel. Its authorized board readers and read tokens have the same access. Other organizations receive `{"changes":[]}`. The server checks the active organization before opening the database. Browsers and observers cannot override the configured channel. This integration works independently of GitHub and folder sharing. OpenBot only needs to be accessible to the NeuroSwarm server.

## Read the work board

`GET /api/v1/work-board` returns `collaboration.changes`, including when you pass `?include=activity`. If OpenBot is absent, the channel is empty, or the database is unavailable, the list is empty and the other parts of the board remain available.

| Field | Meaning |
| --- | --- |
| `changes[].id`, `tasks[].id` | OpenBot task IDs. The change uses the ID of its root task. |
| `title` | A short description of the change or assignment. |
| `status` | The task’s recorded state. The change shows the root task’s own state. |
| `tasks[].agent` | The assigned agent’s recorded name, or a generic label when the name is unavailable. |
| `tasks[].parent_id` | The task that directly delegated this work. The root has `null` here and appears in the list so readers can identify the coordinator. |
| `tasks[].result` | A short summary of the current formal delivery. An empty string means that no matching delivery has been recorded. |
| `updated_at` | Time of the latest available evidence, in Unix seconds. A change includes evidence from its children. A missing timestamp is `null`. |

NeuroSwarm returns up to 12 changes and 48 tasks per change. Open roots and recent requests take priority. Each displayed task must link back to its root. Dates use the request, formal delivery, task timestamp when present, and metadata from the channel’s 512 most recent messages. A status transition without a timestamp may be newer than the displayed time.

## What readers can see

Each request uses a consistent, read-only SQLite snapshot (`mode=ro`, `query_only`). The server reads the selected channel’s task, assignment and result records and the owners’ names. It does not copy those records into its own database or cache them. The HTTP response has `Cache-Control: no-store`.

A result must match the agent, task, channel and current revision. Replaced deliveries are excluded. Ordinary messages contribute timestamps only. Chats, attachments, file contents and tool logs do not appear on the board.

The board uses up to 160 characters for an assignment and 180 for a result. The filter removes recognized paths, links, commands, code blocks and credentials. When no suitable sentence remains, the board shows a generic label. Write objectives and agent names for everyone allowed to read the organization. Sensitive information written as ordinary prose can pass through the filter.

## Check the integration

From the repository root, run the reader and HTTP acceptance tests. The tests include a sample channel and an organization that must see none of its tasks.

```sh
python3 -m unittest discover -s tests -p test_work_collaboration.py -v
python3 -m unittest discover -s tests -p test_collaboration_acceptance.py -v
```
