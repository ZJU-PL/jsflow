"""
Expression IR - Intermediate Representation for constraint expressions.

This module defines the expression data structures used to represent
how values flow through operations in the JavaScript analysis graph.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(kw_only=True)
class Expression:
    """Base expression class."""
    tainted: bool = False


@dataclass
class ConstString(Expression):
    """Constant string expression."""
    value: str = ""


@dataclass
class ConstNumber(Expression):
    """Constant number expression."""
    value: float = 0.0


@dataclass
class Symbol(Expression):
    """Symbol expression representing a graph node."""
    node_id: str = ""
    type_hint: Optional[str] = None  # 'string' | 'number' | None


@dataclass
class Concat(Expression):
    """String concatenation expression."""
    parts: List[Expression] = field(default_factory=list)  # strings


@dataclass
class Add(Expression):
    """Numeric addition expression."""
    terms: List[Expression] = field(default_factory=list)  # numbers


@dataclass
class Sub(Expression):
    """Numeric subtraction expression."""
    left: Expression = None
    right: Expression = None


@dataclass
class Choice(Expression):
    """Choice expression representing multiple options."""
    options: List[Expression] = field(default_factory=list)


@dataclass
class UnknownOp(Expression):
    """Unknown operation expression."""
    op: str = "unknown"
    args: List[Expression] = field(default_factory=list)
