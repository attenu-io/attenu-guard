"""attenu-guard — enforced authority attenuation for multi-agent AI systems.

The open-source answer to OWASP ASI07 (insecure inter-agent communication) and
ASI08 (cascading failures): a child agent's authority can never exceed its
parent's, chains have hard ceilings, and any subtree can be revoked in one
call — enforced in code, offline-verifiable, with a hash-chained audit log.

    from attenu_guard import Authority, Guard, RowLimit, EgressRank

    orchestrator = Guard.issue("orchestrator", Authority(
        scopes={"crm.*", "mail.send"},
        ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600))

    summarizer = orchestrator.delegate("summarizer", Authority(
        scopes={"crm.read"},
        ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900),
        task="summarize Q3 pipeline")

    decision = summarizer.check("crm.read", context={"rows": 4200})
    if not decision:
        print(decision.explain())

    summarizer.enforce("crm.export", context={"egress": "any"})  # raises AuthorityDenied
"""
from .reasons import Decision, Reason, ReasonCode, Disposition
from .ceilings import (
    Ceiling, RowLimit, SpendCap, CallLimit, EgressRank, Allow, Deny, Prefix,
    register_ceiling,
)
from .authority import Authority, AuthorityError
from .guard import Guard, AuthorityDenied
from .audit import AuditLog
from .strikes import StrikePolicy
from . import wire, scenarios, evidence, identity   # stdlib-only submodules (wire needs `cryptography` only for Ed25519)

__version__ = "0.4.1"
__all__ = [
    "Authority", "Guard", "Decision", "Reason", "ReasonCode", "Disposition",
    "AuthorityError", "AuthorityDenied", "AuditLog",
    "Ceiling", "RowLimit", "SpendCap", "CallLimit", "EgressRank", "StrikePolicy",
    "Allow", "Deny", "Prefix", "register_ceiling",
    "wire", "scenarios", "evidence", "identity",
    "__version__",
]
