"""Run the caller's own checks before a rehearsal or a landing and stop at the first one that says no.

A policy is any callable that takes the event dict and returns a pair
(allowed, why). The package ships no policies of its own; the operator
plugs theirs in. Policies run in order; the first (False, why) raises
Refused carrying that why, and no later policy is called. A policy that
returns anything other than a (bool, str) pair is treated as a refusal,
so a broken check can never let a change through. An exception raised
inside a policy is not swallowed: it travels to the caller, which treats
it as a fault and stops.

The event shape:
    {"act": "rehearse" | "land", "target": <absolute path>,
     "candidate_sha256": <lowercase hex>, "pin": <Pin as a dict>}
Each policy receives its own deep copy, so one policy cannot change what
the next one sees.
"""

from __future__ import annotations

import copy
from typing import Callable, Iterable

from .errors import Refused

Policy = Callable[[dict], tuple[bool, str]]

ACTS = ("rehearse", "land")
EVENT_KEYS = ("act", "target", "candidate_sha256", "pin")
PREFIX = "REFUSED: "


def _name(policy: object) -> str:
    """The readable name of a policy for a refusal sentence."""
    for attr in ("__qualname__", "__name__"):
        value = getattr(policy, attr, None)
        if isinstance(value, str) and value:
            return value
    return type(policy).__name__


def _one_sentence(why: str) -> str:
    """Keep a why exactly, folding it onto one line only when it spans lines, with the prefix."""
    flat = " ".join(why.split()) if ("\n" in why or "\r" in why) else why
    if not flat.startswith(PREFIX):
        flat = PREFIX + flat
    return flat


def _check_event(event: object) -> None:
    """Refuse an event that does not have the contract's shape."""
    if not isinstance(event, dict):
        raise Refused(PREFIX + "a policy event must be a dict.")
    missing = [key for key in EVENT_KEYS if key not in event]
    if missing:
        raise Refused(PREFIX + "the policy event lacks " + ", ".join(missing) + ".")
    if event["act"] not in ACTS:
        raise Refused(PREFIX + "the policy event act must be rehearse or land.")


def run(policies: Iterable[Policy], event: dict) -> None:
    """Call every policy on the event in order; raise Refused on the first no."""
    _check_event(event)
    for policy in policies:
        if not callable(policy):
            raise Refused(PREFIX + "a policy in the list is not callable.")
        result = policy(copy.deepcopy(event))
        name = _name(policy)
        if not (isinstance(result, tuple) and len(result) == 2):
            raise Refused(PREFIX + "policy " + name + " did not return an (allowed, why) pair.")
        allowed, why = result
        if not isinstance(allowed, bool):
            raise Refused(PREFIX + "policy " + name + " returned an allowed value that is not True or False.")
        if allowed:
            continue
        if not isinstance(why, str) or not why.strip() or why.strip() == PREFIX.strip():
            raise Refused(PREFIX + "policy " + name + " refused without giving a reason.")
        raise Refused(_one_sentence(why))
