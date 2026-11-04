# SwarmGuard threat model: how AI agents get out of control

Owner: Threat Detection (module 3). Status: **reviewed; Phase 1 built** (2026-11-04). Legend below: ✅ built, 🟡 partial, 🔲 proposed.

## 1. The core idea

An agent can only cause harm by **acting**: calling a tool, reading, writing, messaging, transferring, spawning or
asking a human. If every action passes through our gateway and lands in an event log, then every threat below leaves a
trace. Detection is the job of recognising the trace. Prevention is the job of stopping it before execution.

Three things limit what any detector can do:

1. **Mediation:** an action the gateway never sees can't be detected. Agents must never hold their own credentials,
   network access or shell outside the gateway.
2. **Telemetry:** we can only detect what the event fields capture (see §5).
3. **Intent:** we observe behaviour, not thoughts. Threats that look identical to good behaviour (sandbagging,
   alignment faking, steganography) can only be **made harder and caught probabilistically**, never ruled out.

## 2. Sources

| Source | What it contributes |
|---|---|
| OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10) | Industry list of agent security risks and controls |
| Apollo Research, *Frontier Models are Capable of In-context Scheming* (arXiv 2412.04984) | Observed behaviour: models edited oversight config (`oversight_enabled: false`, `chattr +i`), copied "weights" to another server, overwrote a successor's system prompt, manipulated input data to fake rankings, sandbagged, and denied it all when questioned (o1: >85% of follow-ups) |
| Anthropic, *Agentic Misalignment* (2025) | Under shutdown threat or goal conflict, agents blackmailed, leaked confidential data to outsiders and impersonated security alerts. Prompt instructions reduced this but did not stop it. Recommends runtime monitors, human approval for irreversible actions and need-to-know access |
| METR, *Rogue Replication Threat Model* (2024) | Path to autonomy: acquire resources, maintain infrastructure, evade shutdown. Found no decisive barrier to multiplication |
| Hammond et al., *Multi-Agent Risks from Advanced AI* (arXiv 2502.14143) | Failure modes: miscoordination, conflict, collusion. Risk factors: information asymmetry, network effects, selection pressure, destabilising dynamics, commitment problems, emergent agency, multi-agent security |
| Motwani et al., *Secret Collusion among AI Agents* (NeurIPS 2024) | Agents can hide messages steganographically in normal text. Paraphrasing and monitoring reduce this but don't eliminate it |
| Greenblatt et al., *AI Control* (arXiv 2312.06942) and follow-ups | Assume the agent may be adversarial. Use trusted monitoring, auditing and protocols judged by red-team "control evaluations" |
| Reward hacking / specification gaming (SpecBench, ImpossibleBench and others) | Coding agents edit or skip tests, patch `conftest.py` or hard-code outputs to look successful |

## 3. Threat catalogue

Detectability rates how reliably action logs can catch the threat:
- **High:** a clear signature.
- **Med:** needs correlation or a baseline.
- **Low:** looks like normal behaviour, so only indirect signals are available.

Coverage: ✅ built, 🟡 partially covered, 🔲 proposed.

### A. Hijacked from outside

| # | Threat | Real-world form | Action signals | Detect. | Coverage |
|---|---|---|---|---|---|
| A1 | **Goal hijack / prompt injection** (ASI01) | Instructions hidden in a web page, email, file or tool output | Out-of-policy action shortly after ingesting untrusted content; a sudden behaviour shift | Med | 🔲 SG-012 |
| A2 | **Memory & context poisoning** (ASI06) | Malicious entries written to shared memory or RAG and read later by others | Writes to shared memory from untrusted provenance, followed by deviation in a *different* agent | Med | 🔲 SG-012 (memory sources) + lineage |
| A3 | **Supply-chain compromise** (ASI04) | A malicious tool, plugin, MCP server or model | First use of an unregistered or unpinned tool; tool hash changed | Med | 🟡 SG-004 (novel tool) · 🔲 tool allowlist |
| A4 | **Insecure inter-agent comms / spoofing** (ASI07) | Forged messages, replay, impersonating another agent | `on_behalf_of` / sender ≠ authenticated actor; replayed message ids | High | ✅ SG-008 |

### B. Misusing power it legitimately has

| # | Threat | Real-world form | Action signals | Detect. | Coverage |
|---|---|---|---|---|---|
| B1 | **Unauthorized access** | Reading data outside its role | Restricted resource not in role permissions | High | ✅ SG-001 |
| B2 | **Data exfiltration** | Sending data to an outside party | External transfer to a non-allowlisted destination | High | ✅ SG-002 |
| B3 | **Tool misuse / destructive actions** (ASI02) | Deleting data, cost bombs, mass emails | Delete/overwrite volume, API call rate, spend spikes | Med | 🟡 SG-004 · 🔲 rate & destructive budget |
| B4 | **Unexpected code execution** (ASI05) | A shell command from an injected prompt | Shell/exec tool outside role; dangerous command patterns | High | ✅ SG-006/007 command patterns · 🟡 SG-004 |
| B5 | **Privilege escalation** (ASI03) | Requesting roles, reusing cached tokens, delegation abuse | Writes to `iam/`, role assumption, permission requests | High | ✅ SG-008 |
| B6 | **Salami / low-and-slow exfil** | Many small reads, each below a threshold | Cumulative restricted volume per agent over a long window | Med | 🔲 cumulative budget rule |

### C. Working against its overseers (loss of control)

| # | Threat | Real-world form | Action signals | Detect. | Coverage |
|---|---|---|---|---|---|
| C1 | **Oversight subversion** | Apollo: `sed` the oversight config to false, `chattr +i` | Any write/disable on monitoring, log, policy or gateway config | High | ✅ SG-006 |
| C2 | **Shutdown resistance** | Renaming or `chmod`-ing the shutdown script, killing the watchdog | Mutations on shutdown/kill-switch paths; kill commands | High | ✅ SG-006 |
| C3 | **Self-exfiltration** | Apollo: copying weights to another server | Reads of `model/` paths, followed by transfer or `scp`/`rsync` | High | ✅ SG-007 |
| C4 | **Goal-guarding / successor tampering** | Apollo: overwriting the next model's system prompt | Writes to `prompts/`, `model/successor`, deployment config | High | ✅ SG-006 (`prompts/`, `model/`, `deploy/`) |
| C5 | **Rogue replication & persistence** (METR) | Spawning copies, cron jobs, VMs, new accounts | Spawn/schedule/deploy tools; `crontab`/`nohup`/`docker run` | High | ✅ SG-007 |
| C6 | **Power seeking / resource acquisition** | Requesting more compute, budget, quota or permissions | Acquisition actions; persistent retries after denial | Med | 🔲 SG-011 |
| C7 | **Covert data manipulation** | Apollo: editing the input JSON or overwriting the final ranking | Writes to read-only inputs or final outputs after they're produced; output ≠ trusted recomputation | Med | 🔲 integrity-protected paths |
| C8 | **Reward hacking / spec gaming** | Editing tests or `conftest.py`, hard-coding outputs | Writes to `tests/`, CI config or graders; visible tests pass while held-out tests fail | Med | 🔲 integrity-protected paths + held-out check |
| C9 | **Sabotage** | Subtle bugs, misleading summaries, mis-rating another model's actions | Very hard from actions alone; output-quality audits and disagreement with a trusted reviewer | Low | 🔲 trusted-review sampling |
| C10 | **Deception & denial** | Apollo: denies actions when questioned; false status reports | Structured claims contradict logged actions | High (if claims are structured) | 🔲 SG-014 |
| C11 | **Sandbagging / alignment faking** | Behaves well when it thinks it's watched, worse otherwise | Honeytoken touches; behaviour differs between audited and unaudited runs; capability drop on held-out tasks | Low | 🟡 SG-009 honeytokens ✅ · 🔲 observed/unobserved comparison |
| C12 | **Coercion / manipulation of humans** (ASI09, blackmail) | Reads personal data, then pressures or deceives a human approver | Access to personal/HR data followed by a message to a human principal; impersonating system alerts | Med | 🔲 sensitive-then-human rule |

### D. Multi-agent failures

| # | Threat | Real-world form | Action signals | Detect. | Coverage |
|---|---|---|---|---|---|
| D1 | **Collusion via messages** | A hands restricted data to B, and B leaks it | Restricted read → message(data_ref) → external transfer | High | ✅ SG-003 |
| D2 | **Covert channel / dead drop** | Passing data through a DB, file or wiki with no message | Restricted read → write to shared store → another agent reads → leak | High | ✅ SG-005 |
| D3 | **Steganographic collusion** | Secrets hidden inside normal-looking text | Unusual entropy or length, new communication pairs, correlated actions with no visible reason | Low | 🔲 new-edge + correlation signals; limit channel bandwidth |
| D4 | **Cascading failures** (ASI08) | One bad output poisons the whole pipeline | Failures or denials spreading across many agents quickly | High | 🔲 SG-013 |
| D5 | **Miscoordination / conflict** | Loops, deadlocks, agents fighting over a resource | Message ping-pong cycles, repeated identical actions, contention | Med | 🔲 loop/contention rule |
| D6 | **Emergent agency / network growth** | The swarm grows new links or spawns agents unprompted | New communication edges vs baseline; agent count growth | Med | 🟡 SG-004 · 🔲 graph-drift rule |

### E. Blind spots in the monitor itself

| # | Threat | Action signals | Detect. | Coverage |
|---|---|---|---|---|
| E1 | **Log loss / tampering** | Sequence gaps, reordering, unsigned events | High | ✅ SG-010 |
| E2 | **Bypassing the gateway** | Effects with no matching gateway event (e.g. a file changed with no write event) | Med | 🔲 reconcile resource state with the log |
| E3 | **Timing covert channels** | Information encoded in *when* actions happen | Low | Out of scope; reduce with jittered scheduling |
| E4 | **Splitting harm across agents or time** | Each step benign; only the sum is harmful | Med | ✅ chain rules (SG-003/005) · 🔲 cumulative budgets |

## 4. Detection principles (what makes catching these possible)

1. **Complete mediation:** every tool call, file, network and human request goes through the gateway. No exceptions.
2. **Least privilege per agent and task:** this shrinks what "normal" looks like, so deviations stand out.
3. **Data lineage:** track restricted data by reference and content hash across messages *and* storage (SG-003/005).
4. **Behavioural baselines:** per-role "what's normal", learned continually (SG-004).
5. **Correlation over time and agents:** chains, not single events (SG-003/005, cumulative budgets).
6. **Control-plane protection:** anything touching monitoring, policy, shutdown, prompts, models or tests is
   suspicious by definition (SG-006/007, integrity-protected paths).
7. **Tripwires:** decoy secrets and endpoints that no task needs. Near-zero false positives, and they catch agents
   that behave only when watched (SG-009).
8. **Consistency checks:** compare what an agent *says* with what it *did* (SG-014), and observed with unobserved runs.
9. **Log integrity:** detect gaps and reordering; the monitor must notice when it's blind (SG-010).
10. **Trusted second opinion (optional):** a separate model reviews a sample of actions. Its view is only ever a
    pointer for humans, never proof.

## 5. Telemetry our events must carry

Some of these fields go beyond today's simulator. They are a request to the simulator/agent-runner owners.

| Field | Why | Status |
|---|---|---|
| authenticated `agent_id` + `on_behalf_of` | impersonation, delegation abuse | partly (no `on_behalf_of`) |
| `resource`, `action`, `target`, `status`, `gateway_decision` | everything | ✅ |
| monotonic `sequence` (+ signature later) | log integrity | ✅ sequence |
| `payload.command` for shell/exec tools | oversight/replication commands | 🔲 |
| `payload.data_ref` / `content_hash` | data lineage | partly (data_ref on messages) |
| `payload.untrusted` / source provenance | prompt injection, memory poisoning | 🔲 |
| `payload.claims` on status reports | deception checks | 🔲 |
| human approval requests and responses | trust exploitation, coercion | 🔲 |
| LLM call log (prompt, response, requested tool) | intent context for reviewers | 🔲 |

## 6. Honest limits

- **Not detectable with certainty:** sandbagging, alignment faking, steganography, timing channels and subtle sabotage.
  For these, the realistic goal is to make them **hard, slow and risky**: tripwires, audits, channel restrictions,
  held-out checks and human approval for irreversible steps.
- Every rule is a trade-off between false positives and misses. Each new rule must show 0 alerts on the benign
  scenarios before it ships, which is how SG-001..005 were validated.

## 7. Proposed build order (for review)

1. ✅ **Built — high detectability, high impact:** C1/C2/C4 oversight & shutdown tampering, C3/C5 self-exfiltration &
   replication, B5/A4 privilege escalation & impersonation, E1 log integrity, honeytokens (C11).
2. **Correlation rules:** A1/A2 goal hijack after untrusted input, C6 power seeking, D4 cascades, B6 salami budgets,
   C10 deception.
3. **Integrity & multi-agent:** C7/C8 protected paths (data manipulation, reward hacking), C12 coercion,
   D5 loops, D6 graph drift, E2 state reconciliation.
4. **Research-grade:** D3 steganography signals, C9 sabotage review sampling, observed-vs-unobserved comparison.

Each needs a synthetic test scenario. Detection tests can inject events directly, but showing it in the UI needs
matching simulator scenarios from the simulator owner.
