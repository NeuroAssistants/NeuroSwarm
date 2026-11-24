# Follow a recurring alert

Open **Alerts** and select an **Incident #**. In **Live events**, select an alert and open **Incident # · History**. You can see who owns the incident, what triggered it, whether anyone acknowledged it, and how it ended. If the same rule triggers again after recovery, NeuroSwarm opens a new incident. **Previous incident** takes you back to the earlier one.

## Example: repeated high memory use

The example uses a test machine named `rack-01`. Each row continues the same sequence.

| What happens | What the operator sees |
| --- | --- |
| The observer reports 96% memory use. | Incident 1 opens with one signal. |
| An operator assigns the incident to `oncall`. Another 96% reading arrives. | Incident 1 has two signals and keeps its owner. |
| `first-admin` acknowledges the incident. A 97% reading arrives. | The incident stays acknowledged with three signals. The machine still shows critical memory use. |
| A heartbeat includes total memory only. | The incident stays active because there is no usage reading to confirm recovery. |
| Memory use falls to 72%. | Incident 1 closes. Its history retains the three high readings, owner, acknowledgement and recovery measurement. |
| Memory use reaches 96% again. | Incident 2 opens with one signal and a link to incident 1. The new incident can be assigned and acknowledged. |

Another organization can have a machine with the same name and its own incident 1. Its operators see only their own incidents, history and eligible owners.

## What the history records

NeuroSwarm keeps one active incident (`OPEN` or `ACKED`) for each organization, host and rule. It saves a signal, its occurrence count and its history entry in one transaction. Each received reading that triggers the rule counts as a signal. Heartbeats carry no sample ID, so a retransmitted reading can count again.

The first acknowledgement assigns an unowned incident to the person who acknowledged it. Later signals preserve that acknowledgement and the current owner. Operators can reassign an active incident or leave it unassigned. Historical entries keep the recorded name when someone leaves the organization.

Memory, CPU, process memory and process-count rules need a valid reading below the threshold to recover. A new heartbeat resolves a missing-heartbeat incident. Refreshing the page adds no signals for that same outage. A loop, quota or secret-exposure alert requires an operator to confirm recovery. The history records who confirmed it.

For each signal and recovery, the incident can show the latest recorded agent step on that machine, including the agent, session, action, tool and confirmed relative file paths. That step gives the operator somewhere to look. Timing alone cannot identify who caused the incident. An absent step is shown as unknown. Generic events and file mentions do not establish an edit.

Incident summaries are stored in the organization’s resource database and can outlive the seven-day work journal. They exclude command arguments, conversations, file contents and raw error messages.

## API

| Request | What it does |
| --- | --- |
| `GET /api/v1/alerts?status=ACTIVE` | Lists the latest 100 open or acknowledged incidents. Other choices are `ALL`, `OPEN`, `ACKED` and `RESOLVED`. The default remains `OPEN`. |
| `GET /api/v1/alerts/<id>` | Returns `organization`, `alert`, `history` and `next_before`. History is newest first, in pages of 50. Pass `?before=<next_before>` for the next page. |
| `POST /api/v1/alerts/<id>/owner` | Send `{"owner_id":42}` to assign an operator or administrator, or `{"owner_id":null}` to clear the owner. Operators and administrators can see the eligible owners in `assignees` when they open an active incident. |
| `POST /api/v1/alerts/<id>/ack` | Send `{}` to acknowledge. Returns the updated incident along with `ok`, `alert_id`, `organization` and `host_status`. |
| `POST /api/v1/alerts/<id>/resolve` | Send `{"reason":"operator_verified"}` after verifying recovery. Repeating the request preserves the original actor and time. |

The `alert` object includes `occurrence_count`, `count_is_minimum`, `owner`, `created_at`, `last_seen_at`, `updated_at`, `acked_by`, `acked_at`, `resolved_by`, `resolved_at`, `resolution`, `last_step`, `previous_id` and `evidence`. Times are Unix seconds. `last_seen_at` is the latest triggering signal. The `resolved` history entry contains the recovery evidence. The live feed and history use the same incident ID.

Organization members and read tokens can view incidents. Changes require an operator or administrator session. The UI supplies `organization_id` when reading detail or changing an incident. A stale organization ID returns `409`. Changing a resolved incident also returns `409`, except when repeating a valid resolution.

## Upgrade an existing installation

The server migrates each organization’s resource database to schema version 2 when it opens that database. Table creation, conversion and the recorded schema version are committed together. Existing databases, organization-specific files, observer endpoints and older work-journal records remain usable. Incident context starts once the upgraded journal or remote ingestion records the evidence source.

For older alerts from the same host and rule, a recorded recovery separates incidents. Without a recorded recovery, the records are grouped under the first incident ID. Older IDs still work for lookups and acknowledgements. Original rows remain in `incident_v1_snapshots` for local inspection. The API serves the filtered incident view, and existing audit hashes remain valid.

Older versions overwrote measurements and had no separate owner field. Migrated counts therefore say **At least**. The earliest known human acknowledgement supplies the initial owner. Missing evidence remains unknown.

Before upgrading, stop writers and back up the full instance. To roll back, restore that backup to a new directory and run the older server against it. Later writes remain in the upgraded database. The backup tool includes the main database and each organization’s database. [Backup and restore guide](self-host.md)

```sh
python3 deploy/backup.py snapshot "$STATE_DIR" "$BACKUP_DIR"
python3 deploy/backup.py restore "$SNAPSHOT_DIR" "$RESTORE_DIR"
```

Use the path printed by the first command as `SNAPSHOT_DIR`. Choose a new `RESTORE_DIR`.

## Run the example

From the repository root, with the test browser installed, run the storage, HTTP, concurrency and browser checks. They use temporary local databases, synthetic accounts, and desktop and emulated mobile views. Set `SWARMCONTROL_BROWSER_ARTIFACTS` to a directory if you want to keep a screenshot of the resolved incident. [Browser setup](../tests/BROWSER-TESTS.md)

```sh
python3 -m unittest discover -s tests -p test_incidents.py -v
```
