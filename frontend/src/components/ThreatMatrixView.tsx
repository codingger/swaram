import { useState } from "react";
import { Badge, Card } from "./ui";
import {
  THREAT_CATEGORIES,
  THREAT_RULES,
  BENCHMARK_PROOF,
  type ThreatCategory,
} from "../lib/threatRules";

interface ThreatMatrixViewProps {
  mode?: "all" | "simulator" | "collector" | "detection";
  defaultCategory?: ThreatCategory["key"];
}

export function ThreatMatrixView({
  mode = "all",
  defaultCategory = "data_access",
}: ThreatMatrixViewProps) {
  const [selectedCat, setSelectedCat] = useState<ThreatCategory["key"]>(defaultCategory);
  const [selectedRuleId, setSelectedRuleId] = useState<string>("SG-001");
  const [activeTab, setActiveTab] = useState<"simulator" | "collector" | "detection">(
    mode === "all" ? "simulator" : mode
  );

  const currentCategory = THREAT_CATEGORIES.find((c) => c.key === selectedCat)!;
  const filteredRules = THREAT_RULES.filter((r) => r.category === selectedCat);
  const activeRule = THREAT_RULES.find((r) => r.id === selectedRuleId) ?? filteredRules[0];

  return (
    <Card
      title={
        <div className="flex items-center gap-2">
          <span className="font-semibold text-[var(--text)]">SwaramGuard 20-Rule Threat & Telemetry Matrix</span>
        </div>
      }
      actions={
        <div className="flex items-center gap-2">
          <span className="rounded-full bg-[var(--ok-bg)] border border-[var(--ok)]/20 px-2.5 py-0.5 text-[12px] font-semibold text-[var(--ok)]">
            PASSED: {BENCHMARK_PROOF.testsPassing} Tests
          </span>
          <span className="rounded-full bg-[var(--accent)]/10 border border-[var(--accent)]/20 px-2.5 py-0.5 text-[12px] font-semibold text-[var(--accent)]">
            100% Precision
          </span>
        </div>
      }
    >
      <div className="space-y-4">
        {/* Category Selector Tabs */}
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          {THREAT_CATEGORIES.map((cat) => {
            const isSelected = cat.key === selectedCat;
            const count = THREAT_RULES.filter((r) => r.category === cat.key).length;
            return (
              <button
                key={cat.key}
                onClick={() => {
                  setSelectedCat(cat.key);
                  const firstInCat = THREAT_RULES.find((r) => r.category === cat.key);
                  if (firstInCat) setSelectedRuleId(firstInCat.id);
                }}
                className={`flex flex-col items-start rounded-xl p-3.5 text-left transition-all ${
                  isSelected
                    ? "bg-[var(--card)] ring-2 ring-[var(--accent)] shadow-sm border border-[var(--hairline-subtle)]"
                    : "bg-[var(--card-alt)] hover:bg-[var(--card)] border border-transparent"
                }`}
              >
                <div className="flex w-full items-center justify-between">
                  <span className="font-mono text-[11px] font-bold text-[var(--accent)]">{cat.code}</span>
                  <span className="rounded-full bg-[var(--card)] px-2 py-0.5 text-[11px] font-medium text-[var(--text-2)] border border-[var(--hairline-subtle)]">
                    {count} rules
                  </span>
                </div>
                <div className="mt-2 text-[14px] font-semibold text-[var(--text)]">{cat.label}</div>
                <div className="mt-0.5 line-clamp-1 text-[14px] text-[var(--text-3)]">{cat.description}</div>
              </button>
            );
          })}
        </div>

        {/* Category Description Banner */}
        <div className="flex items-center justify-between rounded-lg bg-[var(--card-alt)] px-3.5 py-2.5 text-[13px] text-[var(--text-2)] border border-[var(--hairline-subtle)]">
          <span><strong className="text-[var(--text)]">{currentCategory.label}</strong> ({currentCategory.code}): {currentCategory.description}</span>
          <span className="shrink-0 text-[var(--text-3)]">Showing {filteredRules.length} rules</span>
        </div>

        {/* Perspective Switcher */}
        {mode === "all" && (
          <div className="flex items-center justify-between border-y border-[var(--hairline-subtle)] py-2">
            <span className="text-[14px] font-medium text-[var(--text-3)]">Operational Perspective:</span>
            <div className="inline-flex rounded-lg bg-[var(--card-alt)] p-0.5 text-[14px] border border-[var(--hairline-subtle)]">
              <button
                onClick={() => setActiveTab("simulator")}
                className={`rounded-md px-3 py-1.5 font-medium transition-all ${
                  activeTab === "simulator"
                    ? "bg-[var(--card)] text-[var(--text)] shadow-xs"
                    : "text-[var(--text-2)] hover:text-[var(--text)]"
                }`}
              >
                1. Simulator Telemetry Contract
              </button>
              <button
                onClick={() => setActiveTab("collector")}
                className={`rounded-md px-3 py-1.5 font-medium transition-all ${
                  activeTab === "collector"
                    ? "bg-[var(--card)] text-[var(--text)] shadow-xs"
                    : "text-[var(--text-2)] hover:text-[var(--text)]"
                }`}
              >
                2. Collector Ingestion Contract
              </button>
              <button
                onClick={() => setActiveTab("detection")}
                className={`rounded-md px-3 py-1.5 font-medium transition-all ${
                  activeTab === "detection"
                    ? "bg-[var(--card)] text-[var(--text)] shadow-xs"
                    : "text-[var(--text-2)] hover:text-[var(--text)]"
                }`}
              >
                3. Detection Logic & Scoring
              </button>
            </div>
          </div>
        )}

        {/* Rule Pills in Selected Category */}
        <div className="flex flex-wrap gap-1.5">
          {filteredRules.map((r) => {
            const isSelected = r.id === activeRule?.id;
            return (
              <button
                key={r.id}
                onClick={() => setSelectedRuleId(r.id)}
                className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-left text-[14px] transition-all border ${
                  isSelected
                    ? "bg-[var(--accent)] font-semibold text-white shadow-xs border-[var(--accent)]"
                    : "bg-[var(--card-alt)] text-[var(--text)] hover:bg-[var(--card)] border-[var(--hairline-subtle)]"
                }`}
              >
                <span className="font-mono text-[12px]">{r.id}</span>
                <span className="truncate max-w-[150px]">{r.name}</span>
                <span
                  className={`h-2 w-2 rounded-full ${
                    r.severity === "critical"
                      ? "bg-[var(--crit)]"
                      : r.severity === "high"
                      ? "bg-[var(--med)]"
                      : "bg-[var(--accent)]"
                  }`}
                />
              </button>
            );
          })}
        </div>

        {/* Active Rule Deep-Dive Pane */}
        {activeRule && (
          <div className="rounded-xl border border-[var(--hairline-subtle)] bg-[var(--card-alt)] p-5">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--hairline-subtle)] pb-3">
              <div className="flex items-center gap-2">
                <span className="font-mono text-[13px] font-bold text-[var(--accent)]">{activeRule.id}</span>
                <span className="text-[15px] font-semibold text-[var(--text)]">{activeRule.name}</span>
              </div>
              <div className="flex items-center gap-2">
                <Badge value={activeRule.severity} />
                <span className="rounded-full bg-[var(--card)] px-2.5 py-0.5 text-[12px] font-medium text-[var(--text-2)] border border-[var(--hairline-subtle)]">
                  {activeRule.detectionLayer}
                </span>
              </div>
            </div>

            <p className="mt-3 text-[14px] leading-relaxed text-[var(--text-2)]">
              {activeRule.description}
            </p>

            {/* Perspective View Content */}
            {activeTab === "simulator" && (
              <div className="mt-4 space-y-3 rounded-lg bg-[var(--card)] p-4 shadow-xs border border-[var(--hairline-subtle)]">
                <div className="flex items-center justify-between">
                  <span className="text-[12px] font-bold uppercase tracking-wider text-[var(--text-3)]">
                    Agent simulator telemetry contract
                  </span>
                  <span className="font-mono text-[12px] text-[var(--text-2)]">
                    event_type: <strong className="text-[var(--text)]">{activeRule.simulatorTelemetry.event_type}</strong> | action: <strong className="text-[var(--text)]">{activeRule.simulatorTelemetry.action}</strong>
                  </span>
                </div>

                <div>
                  <div className="text-[14px] font-semibold text-[var(--text-2)]">Attack Behavior Pattern:</div>
                  <div className="mt-1 rounded-md bg-[var(--med-bg)] border border-[var(--med)]/20 px-3 py-2 text-[13px] font-medium text-[var(--med)]">
                    {activeRule.simulatorTelemetry.attackPattern}
                  </div>
                </div>

                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <div className="text-[14px] font-semibold text-[var(--text-2)]">Required Event Fields:</div>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {activeRule.simulatorTelemetry.requiredFields.map((f) => (
                        <span key={f} className="rounded bg-[var(--card-alt)] px-2 py-0.5 font-mono text-[12px] text-[var(--text)] border border-[var(--hairline-subtle)]">
                          {f}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div>
                    <div className="text-[14px] font-semibold text-[var(--text-2)]">Sample Agent Payload:</div>
                    <pre className="mt-1 overflow-x-auto rounded bg-[var(--card-alt)] p-2 font-mono text-[12px] text-[var(--text)] border border-[var(--hairline-subtle)]">
                      {JSON.stringify(activeRule.simulatorTelemetry.samplePayload ?? {}, null, 2)}
                    </pre>
                  </div>
                </div>
              </div>
            )}

            {activeTab === "collector" && (
              <div className="mt-4 space-y-3 rounded-lg bg-[var(--card)] p-4 shadow-xs border border-[var(--hairline-subtle)]">
                <div className="flex items-center justify-between">
                  <span className="text-[12px] font-bold uppercase tracking-wider text-[var(--text-3)]">
                    Event collector validation contract
                  </span>
                  <span className="font-mono text-[12px] text-[var(--text-2)]">
                    Index Key: <strong className="text-[var(--text)]">{activeRule.collectorOptimization.targetIndex}</strong>
                  </span>
                </div>

                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="rounded-md bg-[var(--accent)]/5 p-3 border border-[var(--accent)]/15">
                    <div className="text-[14px] font-bold text-[var(--accent)]">1. Intake Validation Check</div>
                    <div className="mt-1 text-[13px] text-[var(--text-2)]">
                      {activeRule.collectorOptimization.validationCheck}
                    </div>
                  </div>

                  <div className="rounded-md bg-[var(--ok-bg)] p-3 border border-[var(--ok)]/20">
                    <div className="text-[14px] font-bold text-[var(--ok)]">2. Normalization & Storage Optimization</div>
                    <div className="mt-1 text-[13px] text-[var(--text-2)]">
                      {activeRule.collectorOptimization.normalizationStep}
                    </div>
                  </div>
                </div>

                <div className="text-[12px] text-[var(--text-3)]">
                  <em>Note: The Collector enforces strict UTC ISO timestamps, deduplicates by (run_id, event_id), and generates sha256 evidence hashes.</em>
                </div>
              </div>
            )}

            {activeTab === "detection" && (
              <div className="mt-4 space-y-3 rounded-lg bg-[var(--card)] p-4 shadow-xs border border-[var(--hairline-subtle)]">
                <div className="flex items-center justify-between">
                  <span className="text-[12px] font-bold uppercase tracking-wider text-[var(--text-3)]">
                    Threat detection contract
                  </span>
                  <span className="rounded-full bg-[var(--card-alt)] px-2.5 py-0.5 text-[12px] font-semibold text-[var(--text-2)] border border-[var(--hairline-subtle)]">
                    {activeRule.detectionLayer}
                  </span>
                </div>

                <div className="grid gap-3 sm:grid-cols-3">
                  <div className="rounded-md bg-[var(--card-alt)] p-3 border border-[var(--hairline-subtle)]">
                    <div className="text-[14px] font-semibold text-[var(--text-2)]">Detection Method</div>
                    <div className="mt-1 text-[14px] font-medium text-[var(--text)]">{activeRule.detectionLayer}</div>
                  </div>
                  <div className="rounded-md bg-[var(--card-alt)] p-3 border border-[var(--hairline-subtle)]">
                    <div className="text-[14px] font-semibold text-[var(--text-2)]">Evidence Requirement</div>
                    <div className="mt-1 text-[14px] font-medium text-[var(--text)]">Strict event_id correlation</div>
                  </div>
                  <div className="rounded-md bg-[var(--card-alt)] p-3 border border-[var(--hairline-subtle)]">
                    <div className="text-[14px] font-semibold text-[var(--text-2)]">False Alarm Target</div>
                    <div className="mt-1 text-[14px] font-bold text-[var(--ok)]">0% on benign baseline</div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </Card>
  );
}
