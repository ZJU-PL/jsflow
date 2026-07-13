"""
Shared utility classes and constants for probejs.

This module contains light-weight data carriers (e.g., NodeHandleResult,
BranchTag), small enums, and helpers for representing intermediate state during
AST handling and data-flow tracking. Keeping them here avoids circular imports
between core modules such as graph and opgen.
"""

import re
from typing import List, Tuple, TypeVar, NoReturn
from enum import Enum
import math
import secrets
from collections import defaultdict


class NodeHandleResult:
    """
    Object for storing AST node handling result.

    This class is the primary return type for AST node handlers. It encapsulates
    all information produced when handling a node during symbolic execution,
    including:
    - Object nodes created or referenced
    - Variable names and name nodes involved
    - Literal values extracted
    - Objects used during evaluation
    - Branch and taint tracking information

    The class is used throughout the analysis to pass results between handlers
    and to track state during execution. It supports optional printing via
    the print_callback class variable.

    Args:
        obj_nodes (list, optional): Object nodes created or referenced by this
            node. These represent JavaScript objects in the object graph.
            Defaults to [].
        values (list, optional): Literal values of the variable or expression
            (as JavaScript source code, e.g. strings are quoted). Used for
            constants and literals. Defaults to [].
        name (str, optional): Variable name if this node represents a variable
            reference or declaration. Defaults to None.
        name_nodes (list, optional): Name nodes (variable nodes) involved in
            this operation. Name nodes connect to object nodes via NAME_TO_OBJ
            edges. Defaults to [].
        used_objs (list, optional): Object nodes used during evaluation of this
            node. This tracks dependencies for data flow analysis. Defaults to [].
        from_branches (list, optional): Experimental. Branch tags indicating
            which execution branches these object nodes come from. Used for
            path-sensitive analysis. Defaults to [].
        value_tags (list, optional): Experimental. Tags for values, used for
            tracking value sources or transformations. Defaults to [].
        ast_node (optional): AST node ID that produced this result. If not None,
            results will be printed using print_callback. Set the class variable
            'print_callback' to customize print format. Defaults to None.
        name_tainted (bool, optional): Whether the variable name itself is
            tainted (e.g., from user input). Defaults to None.
        parent_is_proto (bool, optional): Whether the parent object is a
            prototype. Used for prototype pollution detection. Defaults to None.
        terminated (bool, optional): Whether execution should terminate after
            this node (e.g., return, throw). Defaults to None.
        multi_assign (bool, optional): Whether this is a multi-assignment
            operation. Defaults to False.
        tampered_prop (bool, optional): Whether a property was tampered with
            (for internal property tampering detection). Defaults to False.
        exit_nodes (list, optional): Control flow exit nodes for this operation.
            Defaults to False (should be list).

    Example:
        >>> # Create result for a variable reference
        >>> result = NodeHandleResult(
        ...     obj_nodes=[obj1, obj2],
        ...     name="x",
        ...     name_nodes=[name_node]
        ... )
        >>> # Create result for a literal
        >>> literal_result = NodeHandleResult(
        ...     obj_nodes=[string_obj],
        ...     values=["'hello'"]
        ... )
    """

    @staticmethod
    def _print(handle_result):
        print(str(handle_result))

    print_callback = _print

    def __init__(self, **kwargs):
        self.obj_nodes = kwargs.get("obj_nodes", [])
        self.values = kwargs.get("values", [])
        self.name = kwargs.get("name")
        self.name_nodes = kwargs.get("name_nodes", [])
        self.used_objs = kwargs.get("used_objs", [])
        self.from_branches = kwargs.get("from_branches", [])
        self.value_tags = kwargs.get("value_tags", [])
        self.value_sources = kwargs.get("value_sources", [])
        self.ast_node = kwargs.get("ast_node")
        self.name_tainted = kwargs.get("name_tainted")
        self.parent_is_proto = kwargs.get("parent_is_proto")
        self.terminated = kwargs.get("terminated")
        self.multi_assign = kwargs.get("multi_assign", False)
        self.tampered_prop = kwargs.get("tampered_prop", False)
        self.exit_nodes = kwargs.get("exit_nodes", False)
        assert type(self.obj_nodes) == list
        assert type(self.used_objs) == list
        if self.ast_node:
            self.print_callback()
        if self.values and not self.value_sources:
            self.value_sources = [[]] * len(self.values)
        callback = kwargs.get("callback")
        if callback:
            callback(self)

    def __bool__(self):
        return bool(
            self.obj_nodes
            or self.values
            or (self.name is not None)
            or self.name_nodes
            or self.used_objs
        )

    def __repr__(self):
        s = []
        for key in dir(self):
            if (
                not key.startswith("_")
                and not callable(getattr(self, key))
                and getattr(self, key)
            ):
                s.append(f"{key}={repr(getattr(self, key))}")
        args = ", ".join(s)
        return f"{self.__class__.__name__}({args})"


class BranchTag:
    """
    Class for tagging branches in path-sensitive analysis.

    BranchTag represents a point in the execution where the program can take
    different paths (e.g., if/else, switch cases, loop iterations). It tracks:
    - The branching point (which statement)
    - Which branch was taken
    - The operation mark (what happened in this branch)

    Branch tags are used throughout the analysis to:
    - Track which objects exist in which execution paths
    - Enable path-sensitive data flow analysis
    - Support branch-aware object copying
    - Filter objects based on current execution path

    The string representation format is: "{point}#{branch}{mark}"
    Example: "If123#0A" means "if statement 123, true branch (0), addition (A)"

    Args:
        point (str): ID of the branching point AST node (e.g., "If123",
            "Switch456", "For789"). Identifies which conditional/loop statement.
        branch (str): Which branch was taken. For if statements: "0" for true,
            "1" for false. For switch: case number. For loops: iteration info.
        mark (str): Operation mark indicating what happened:
            - 'A' (Addition): Object was assigned/added in this branch
            - 'D' (Deletion): Object was removed/not valid in this branch
            - 'L' (Loop): Object is a loop variable
            - 'P' (Parent): Object is from parent loop
            - 'C' (Created): Object was created in this loop iteration
        ---
        Alternative initialization:
        s (str/BranchTag): String representation to parse (e.g., "If123#0A"),
            or another BranchTag to copy. If provided, point/branch/mark are
            parsed from the string or copied from the tag.

    Example:
        >>> # Create tag for if statement true branch
        >>> tag = BranchTag(point="If123", branch="0", mark="A")
        >>> # Parse from string
        >>> tag2 = BranchTag("If123#0A")
        >>> # Use in branch container
        >>> branches = BranchTagContainer([tag])
    """

    def __init__(self, s=None, **kwargs):
        self.point = None
        self.branch = None
        self.mark = None
        if s:
            try:
                self.point, self.branch, self.mark = re.match(
                    r"-?([^#]*)#(\d*)(\w?)", str(s)
                ).groups()
                if self.point == "":
                    self.point = None
                if self.branch == "":
                    self.branch = None
                if self.mark == "":
                    self.mark = None
            except Exception:
                pass
        if "point" in kwargs:
            self.point = kwargs["point"]
        if "branch" in kwargs:
            self.branch = str(kwargs["branch"])
        if "mark" in kwargs:
            self.mark = kwargs["mark"]
        # assert self.__bool__()

    def __str__(self):
        return "{}#{}{}".format(
            self.point if self.point is not None else "",
            self.branch if self.branch is not None else "",
            self.mark if self.mark is not None else "",
        )

    def __repr__(self):
        return f'{self.__class__.__name__}("{self.__str__()}")'

    def __hash__(self):
        return hash(self.__repr__())

    def __bool__(self):
        return bool(self.point and self.branch)

    def __eq__(self, other):
        return str(self) == str(other)


class BranchTagContainer(list):
    """
    Experimental. An extension to list that contains branch tags.
    """

    def __add__(self, other):
        return BranchTagContainer(list.__add__(self, other))

    def __repr__(self):
        return f"{self.__class__.__name__}({list.__repr__(self)})"

    def __str__(self):
        return list.__repr__(self)

    def __bool__(self):
        return len(self) != 0

    def get_last_choice_tag(self):
        """
        Get the last choice statement (if/switch) tag.
        """
        for i in reversed(self):
            if i.point.startswith("If") or i.point.startswith("Switch"):
                return i
        return None

    def get_last_for_tag(self):
        """
        Get the last for statement or forEach tag.
        """
        for i in reversed(self):
            if i.point.startswith("For"):
                return i
        return None

    def get_choice_tags(self):
        """
        Get all choice statement (if/switch) tags.
        """
        return BranchTagContainer(
            filter(
                lambda i: i.point.startswith("If") or i.point.startswith("Switch"), self
            )
        )

    def get_for_tags(self):
        """
        Get all for statement or forEach tags.
        """
        return BranchTagContainer(filter(lambda i: i.point.startswith("For"), self))

    def get_creating_for_tags(self):
        """
        Get all choice statement (if/switch) tags with an 'C' mark.
        """
        return BranchTagContainer(
            filter(lambda i: i.point.startswith("For") and i.mark == "C", self)
        )

    def set_marks(self, mark):
        """
        Set all tags' marks to a new mark.
        """
        for tag in self:
            tag.mark = mark
        return self

    def get_matched_tags(self, target, level=2):
        """
        Get tags matching with tags in 'target'.

        Args:
            target (Iterable): Target container.
            level (int, optional): Matching level.
                1: Only point matches.
                2: Point and branch match.
                3: Point, branch and mark match.
                Defaults to 2.

        Returns:
            BranchTagContainer: all matching tags.
        """
        result = []
        for i in self:
            for j in target:
                flag = True
                if level >= 1 and i.point != j.point:
                    flag = False
                if level >= 2 and i.branch != j.branch:
                    flag = False
                if level >= 3 and i.mark != j.mark:
                    flag = False
                if flag:
                    result.append(i)
                    break
        return BranchTagContainer(set(result))

    def match(
        self, tag: BranchTag = None, point=None, branch=None, mark=None
    ) -> Tuple[int, BranchTag]:
        """
        Find a matching BranchTag in the array.

        Use either a BranchTag or three strings as argument.

        Returns:
            Tuple[int, BranchTag]: index and the value of the matching
            BranchTag.
        """
        if tag:
            point = tag.point
            branch = tag.branch
            mark = tag.mark
        for i, t in enumerate(self):
            if t.point == point and t.branch == branch:
                if mark is None or t.mark == mark:
                    return i, t
        return None, None

    def append(self, tag=None, point=None, branch=None, mark=None):
        if tag is not None:
            list.append(tag)
        elif point != None and branch != None:
            list.append(BranchTag(point=point, branch=branch, mark=mark))

    def is_empty(self):
        return not bool(self)


class ExtraInfo:
    """
    Carries additional context information during AST handling and graph construction.

    This class passes around contextual state that isn't captured by the graph
    structure itself, such as:
    - Current execution branch/path constraints (branches)
    - Which "side" of an assignment we are on (left/right)
    - Parent object context for property access
    - Caller AST node information
    - Switch statement context variables
    - Class definition context

    Args:
        original (ExtraInfo, optional): An existing ExtraInfo object to copy from.
        **kwargs: Individual fields to override or set.
            - branches (BranchTagContainer): Path constraints.
            - side (str): 'left' or 'right'.
            - parent_obj (str): ID of parent object node.
            - caller_ast (str): ID of function caller AST node.
            - switch_var (NodeHandleResult): Variable being switched on.
            - class_obj (str): ID of class object node being defined.
    """
    def __init__(self, original=None, **kwargs):
        self.branches = BranchTagContainer()
        self.side = None
        self.parent_obj = None
        self.caller_ast = None
        self.switch_var = None
        self.class_obj = None
        if original is not None:
            self.branches = original.branches
            self.side = original.side
            self.parent_obj = original.parent_obj
            self.caller_ast = original.caller_ast
            self.switch_var = original.switch_var
            self.class_obj = original.class_obj
        if "branches" in kwargs:
            self.branches = kwargs.get("branches")
        if "side" in kwargs:
            self.side = kwargs.get("side")
        if "parent_obj" in kwargs:
            self.parent_obj = kwargs.get("parent_obj")
        if "caller_ast" in kwargs:
            self.caller_ast = kwargs.get("caller_ast")
        if "switch_var" in kwargs:
            self.switch_var = kwargs.get("switch_var")
        if "class_obj" in kwargs:
            self.class_obj = kwargs.get("class_obj")

    def __bool__(self):
        return bool(
            self.branches
            or (self.side is not None)
            or (self.parent_obj is not None)
            or (self.caller_ast is not None)
            or (self.switch_var is not None)
        )

    def __repr__(self):
        s = []
        for key in dir(self):
            if not key.startswith("__"):
                s.append(f"{key}={repr(getattr(self, key))}")
        args = ", ".join(s)
        return f"{self.__class__.__name__}({args})"


class ValueRange:
    """
    Represents a numeric range for abstract interpretation of values.

    Used to track possible ranges of numeric variables to detect potential
    overflows or out-of-bounds access, though currently basic.

    Args:
        original (ValueRange, optional): Existing range to copy.
        **kwargs:
            - min (float): Minimum value. Defaults to -inf.
            - max (float): Maximum value. Defaults to +inf.
            - type (str): 'float' or 'int'. Defaults to 'float'.
    """
    def __init__(self, original=None, **kwargs):
        self.min = kwargs.get("min", -math.inf)
        self.max = kwargs.get("max", math.inf)
        self.type = kwargs.get("type", "float")


class DictCounter(defaultdict):
    """
    A dictionary subclass that defaults to 0 and formats output for logging.
    Useful for counting events or object occurrences.
    """
    def __init__(self):
        super().__init__(lambda: 0)

    def gets(self, key, val=0):
        """Get value formatted as 'key:value'."""
        value = super().get(key, val)
        return f"{key}:{value}"

    def __repr__(self):
        return f"{self.__class__.__name__}({dict(self)})"


def get_random_hex(length=6):
    """Generate a random hex string of given length."""
    return secrets.token_hex(length // 2)


class _SpecialValue(object):
    """
    Internal wrapper for special symbolic values (e.g., wildcard, undefined).
    Ensures these values have unique identity and string representation.
    """
    def __init__(self, alt):
        self.alt = alt
        self._hash = get_random_hex()

    def __str__(self):
        return self.alt

    def __repr__(self):
        return self.alt

    def __eq__(self, value):
        if type(value) == _SpecialValue:
            return self.alt == value.alt
        else:
            return False

    def __hash__(self):
        return hash(self._hash)


wildcard = _SpecialValue("*")
wildcard_f = _SpecialValue("*")  # wildcard filtered by hasOwnProperty
undefined = _SpecialValue("undefined")


class JSSpecialValue(Enum):
    """
    Enum representing JavaScript special types and values.
    Used for type tagging and checking.
    """
    # deprecated
    UNDEFINED = 0
    NULL = 1
    NAN = 10
    INFINITY = 11
    NEGATIVE_INFINITY = 12
    TRUE = 20
    FALSE = 21
    OBJECT = 100
    FUNCTION = 101


class ConditionTag:
    """
    Tags a condition result with the operation type and operands involved.

    Used in path-sensitive analysis to record *why* a branch was taken or
    what condition needs to be satisfied for a path. It stores the logical
    operation (OR, AND, NOT, comparison) and the values involved.
    """
    logical_or = binary_bool_or = "LogicalOr"
    logical_and = binary_bool_and = "LogicalAnd"
    logical_not = unary_bool_or = "LogicalNot"

    bitwise_or = binary_bitwise_or = "BitwiseOr"
    bitwise_and = binary_bitwise_and = "BitwiseAnd"

    equality = binary_is_equal = "AbstractEquality"
    strict_equality = binary_is_identical = "StrictEquality"
    inequality = binary_is_not_equal = "AbstractEqual"
    strict_inequality = binary_is_not_identical = "StrictInequality"
    less_than = binary_is_smaller = "LessThan"
    greater_than = binary_is_smaller = "GreaterThan"
    less_than_or_equal = binary_is_smaller_or_equal = "LessThanOrEqual"
    greater_than_or_equal = binary_is_smaller_or_equal = "GreaterThanOrEqual"

    exp_value = "ExpressionValue"

    def __init__(self, op, val1, val2=None):
        self.op = op
        self.val1 = val1
        self.val2 = val2

    def __repr__(self):
        if self.val2 is not None:
            return (
                f"{self.__class__.__name__}("
                f"{repr(self.op)}, {repr(self.val1)}, {repr(self.val2)})"
            )
        else:
            return f"{self.__class__.__name__}({repr(self.op)}, {repr(self.val1)})"
