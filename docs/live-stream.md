# Live stream: contract for the live UI

Everything that happens in a run is pushed to the UI the moment it happens: each agent action, each detection, each
pause or hold, each quarantined input. It works the same for simulated runs and for real agents reporting through the
ingest API. A reference page lives at **Live monitor** (`frontend/src/pages/LivePage.tsx`), with a reusable hook in
`frontend/src/lib/live.ts`.

## Connect

```
WebSocket  /api/live                 every run
WebSocket  /api/live?run_id=run-…    one run
WebSocket  /api/live?since=<seq>     replay everything after <seq> (resume after a reconnect)
```

On connect you get `hello`, then the recent history (up to 2000 messages), then live messages. Use `seq` to drop
duplicates after a reconnect (`useLiveStream()` does this for you).

```ts
import { useLiveStream } from "../lib/live";
const { messages, connected } = useLiveStream(runId); // runId optional
```

In dev the Vite proxy forwards WebSockets (`ws: true` in `vite.config.ts`).

## Start a run without waiting

```
POST /api/runs/start      body: ScenarioConfig (same as /api/simulate)  ->  {"run_id": "run-…", "stream": "/api/live"}
GET  /api/live/active     runs in progress
```

The call returns at once; the run streams. Use `live_guard: "contain"` to see attackers being stopped, and
`auto_pipeline: true` to have alerts, response and evaluation ready when it finishes. Gemini runs are refused up front
if today's quota can't cover them (`GET /api/gemini/quota`).

## Message envelope

```json
{"type": "event", "seq": 42, "ts": "2026-11-05T12:00:00.123Z", "run_id": "run-1a2b3c4d", "data": {}}
```

`seq` is global and strictly increasing. `run_id` is null only for messages about the whole system (`quota`).

| type | when | `data` |
|---|---|---|
| `hello` | on connect | `{subscribers}` |
| `run_started` | a run begins | `{config}`: the ScenarioConfig, or `{scenario_id, source: "ingest", live_guard, agent_count}` |
| `run_agents` | right after | `{agents: [{agent_id, name, role, permissions}]}` |
| `event` | every agent action, as it happens | `{event_id, agent_id, timestamp, event_type, action, status, target, resource, sequence, gateway_decision, payload}`. `status: "denied"` with `payload.quarantined` means it was **blocked before it ran**. `payload.ai_trace` says why a model-driven agent acted. |
| `detection` | a rule fires for the first time on some agents | `{sequence, timestamp, event_id, rule_id, rule_name, severity, agent_ids, reason}` (empty `agent_ids` = run-level, e.g. SG-026) |
| `containment` | an agent is paused, or its outbound transfers held | `{agent_id, role, scope: "agent"\|"egress", trigger: "risk"\|"hijack_tripwire"\|"need_to_know", paused_at_sequence, risk, explanation, blocked_actions}` |
| `quarantine` | an untrusted input was withheld before the agent read it | `{agent_id, resource, claimed_sender, sequence}` |
| `response` | the response policy acted on a new alert, live | `{sequence, rule_id, rule_name, severity, decision, agent_ids, applied}`; `applied` is e.g. `["paused"]`, `["egress held"]`, `["recorded"]`, or `["would_pause"]` in detect mode |
| `operator` | a person paused an agent / held its egress from the UI | `{agent_id, action, result, note}` |
| `review` | a review item was created or decided | `{action: "created"\|"decided", item}` (see the review queue) |
| `quota` | after a Gemini run | the `/api/gemini/quota` object |
| `run_finished` | the run is done (and saved, and processed if `auto_pipeline`) | `{persisted, counts, stages, live_metrics, alerts, ground_truth}`. `live_metrics.data_left_the_system` is the headline. `ground_truth` is for demo scoring only. |
| `run_failed` | the run crashed | `{error}` |

Suggested UI: an agent grid that turns amber on `detection` and red on `containment`; a feed of `event`s where
`status: "denied"` is shown as blocked; toasts for `detection`, `containment` and `quarantine`; a banner on
`run_finished` with whether data left the system.

## Operator controls (while a run is live)

```
POST /api/live/{run_id}/agents/{agent_id}   {"action": "pause" | "hold_egress", "note": "..."}  -> {"result": "paused"}
POST /api/live/{run_id}/stop                {"note": "..."}  -> pauses every agent (kill switch)
```

Only for runs started with `live_guard: "contain"` that are still running (409 otherwise). Each action is published
as `containment` + `operator`, and lands in the review queue (`GET /api/reviews`, release / confirm).

## Real agents (live ingest)

An external agent platform reports into the same pipeline and stream:

```
POST /api/ingest/sessions     {"name": "crew-demo", "live_guard": "contain",
                               "agents": [{"agent_id": "a1", "role": "analyst", "permissions": ["data/customer_pii"]}]}
                              -> {"run_id": "run-…", "stream": "/api/live?run_id=run-…"}
POST /api/ingest/{run_id}/gate    {"agent_id", "event_type", "action", "resource", "target", "payload"}
                              -> {"allow": false, "reason": "egress held since event #3: …"}   (ask BEFORE acting)
POST /api/ingest/{run_id}/events  [{"agent_id", "event_type", "action", "resource", "target", "payload"}, …]
                              -> {"accepted", "denied", "new_detections", "paused_agents", "held_egress"}
POST /api/ingest/{run_id}/finish  -> runs collect, detect, respond, evaluate; publishes run_finished
```

`event_type` is one of `message`, `tool_call`, `resource_access`, `data_transfer`, `task`. `event_id`, `timestamp` and
`sequence` are filled in if missing.

## Performance

The live guard re-checks every rule over the run so far after each event, so its cost grows with the square of the
run length. Four caches remove the repeated work without changing any result (all 206 snapshotted outputs, alerts,
risk scores, live decisions and benchmark numbers, are identical before and after): timestamp parsing, SG-020's text
scan, one log-coverage index per detection pass, and one-pass per-agent facts in risk scoring.

| Live guard, `sg003_leak_chain` | Before | After |
|---|---|---|
| 5 agents (80 events) | 405 ms | 104 ms |
| 10 agents (177 events) | 1.7 s | 0.41 s |
| 20 agents (369 events) | 7.6 s | 1.6 s |

Very long sessions (thousands of events) would still slow down; the next step would be evaluating the heavy rules over
a recent window, which trades exactness on whole-run rules (e.g. SG-016 salami) and so is not done yet.
