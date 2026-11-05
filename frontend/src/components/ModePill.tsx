import { Lock } from "lucide-react";
import type { ResponseDecision, ResponsePolicyMode } from "../types";

export interface ModePillProps {
  mode: ResponsePolicyMode | string;
  decision?: ResponseDecision | string;
  className?: string;
}

export function ModePill({ mode, decision, className = "" }: ModePillProps) {
  // STRICT RULE: "Blocked at gateway" ONLY when mode === "enforced"
  const isEnforced = mode === "enforced";

  if (isEnforced) {
    return (
      <span
        className={`inline-flex items-center gap-1.5 rounded-full bg-[var(--ok-bg)] px-3 py-1 text-[14px] font-medium text-[var(--ok)] border border-[var(--ok)]/30 ${className}`}
      >
        <Lock size={12} strokeWidth={2} />
        <span>Blocked at gateway</span>
      </span>
    );
  }

  // Simulation / Policy config mode - NEVER render the word "blocked"
  let label = "Alert only";
  if (decision === "block" || decision === "would_block") {
    label = "Would deny (replay)";
  } else if (decision === "pause" || decision === "would_pause") {
    label = "Would pause (replay)";
  }

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border border-dashed border-[var(--hairline)] bg-transparent px-3 py-1 text-[14px] font-medium text-[var(--text-2)] ${className}`}
    >
      <span>{label}</span>
    </span>
  );
}
