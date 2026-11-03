"""Policy gateway consulted *before* a protected tool executes.

`monitor` mode lets the request through and records `would_block`.
`enforce` mode denies it; only then does the event carry `blocked` / `denied`.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.modules.simulator.world import EXTERNAL_ALLOWLIST, EXTERNAL_PREFIX, RESTRICTED_RESOURCES
from app.schemas import Agent, GatewayMode


@dataclass(frozen=True)
class GatewayResult:
    decision: str  # not_checked | allow | would_block | blocked
    reason: str

    @property
    def executes(self) -> bool:
        return self.decision != "blocked"


class PolicyGateway:
    def __init__(
        self,
        mode: GatewayMode = "monitor",
        restricted: list[str] | None = None,
        external_allowlist: list[str] | None = None,
    ):
        self.mode = mode
        self.restricted = set(restricted if restricted is not None else RESTRICTED_RESOURCES)
        self.allowlist = set(external_allowlist if external_allowlist is not None else EXTERNAL_ALLOWLIST)

    def is_protected(self, resource: str | None, target: str | None) -> bool:
        return (resource in self.restricted) or bool(target and target.startswith(EXTERNAL_PREFIX))

    def check(self, agent: Agent, resource: str | None = None, target: str | None = None) -> GatewayResult:
        if self.mode == "off" or not self.is_protected(resource, target):
            return GatewayResult("not_checked", "unprotected action or gateway off")

        violation = None
        if target and target.startswith(EXTERNAL_PREFIX) and target not in self.allowlist:
            violation = f"destination {target} is not on the external allowlist"
        elif resource in self.restricted and resource not in agent.permissions:
            violation = f"role {agent.role} has no permission for {resource}"

        if violation is None:
            return GatewayResult("allow", "permitted by role policy")
        if self.mode == "enforce":
            return GatewayResult("blocked", violation)
        return GatewayResult("would_block", violation)
