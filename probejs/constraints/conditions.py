"""
Condition IR - Intermediate Representation for path conditions.

This module defines the condition data structures used to represent
path-sensitive constraints in the analysis.
"""

from dataclasses import dataclass, field
from typing import List, Union

from .expressions import Expression


@dataclass
class Condition:
    """Base class for path conditions."""


@dataclass
class TrueCondition(Condition):
    """Represents a tautology (always true)."""


@dataclass
class FalseCondition(Condition):
    """Represents a contradiction (always false)."""


@dataclass
class Predicate(Condition):
    """
    Atomic predicate over expressions or literal values.
    """
    op: str  # eq, neq, lt, le, gt, ge, contains, not_contains, prefix, suffix, regex
    left: Union[Expression, str, float, int]
    right: Union[Expression, str, float, int, None] = None


@dataclass
class NamedCondition(Condition):
    """
    A named guard when no structured predicate is available.
    """
    name: str


@dataclass
class NotCondition(Condition):
    inner: Condition


@dataclass
class AndCondition(Condition):
    parts: List[Condition] = field(default_factory=list)


@dataclass
class OrCondition(Condition):
    parts: List[Condition] = field(default_factory=list)


@dataclass
class PathConstraint:
    """
    A path-sensitive constraint: value expression + accumulated path condition.
    """
    expr: Expression
    condition: Condition = field(default_factory=TrueCondition)
