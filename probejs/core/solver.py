"""
Constraint solving helpers built on top of z3.

This module reconstructs symbolic constraints from the CONTRIBUTES_TO edges in
the analysis graph to reason about possible concrete values at sinks. It is
invoked by vulnerability checks to see whether an attack payload can satisfy
the derived equations (strings, numbers, or mixed types).
"""

from . import opgen
from .graph import Graph
from ..utils.utilities import wildcard
from collections import defaultdict
from functools import reduce
from operator import add
import sty
import re
import z3
import time


class MixedSymbol:
    """Thin wrapper that holds both string and numeric z3 symbols for a node."""

    def __init__(self, name, _type=None):
        super().__init__()
        self._number = None
        self._string = None
        if _type == "number":
            self._number = z3.Real(f"n{name}")
        elif _type == "string":
            self._string = z3.String(f"s{name}")
        else:
            self._number = z3.Real(f"n{name}")
            self._string = z3.String(f"s{name}")

    def number(self):
        return self._number

    def string(self):
        return self._string


def check_number_operation(arr):
    for i in arr:
        if type(i) is not MixedSymbol:
            return False
        elif i.number() is None:
            return False
    return True


def check_string_operation(arr):
    for i in arr:
        if type(i) is not MixedSymbol:
            return False
        elif i.string() is None:
            return False
    return True


def solve2(G: Graph, final_objs, initial_objs=None, contains=True):
    """
    Solve constraints to determine if vulnerable paths are feasible and generate exploits.

    This function builds a Z3 constraint system from the CONTRIBUTES_TO edges in the
    graph, modeling how values flow through operations like string concatenation and
    numeric addition. It then solves the constraints to:
    1. Determine if a vulnerable path is actually reachable (feasibility)
    2. Generate concrete input values that would trigger the vulnerability (exploit)

    The constraint system is built by:
    - Following CONTRIBUTES_TO edges backward from sink objects
    - Modeling operations (string_concat, numeric_add) as Z3 constraints
    - Adding constraints for literal values found in the graph
    - Applying extra constraints from G.extra_constraints

    Args:
        G (Graph): The graph object containing the analysis results
        final_objs (list): List of sink object node IDs to solve for. These are
            the objects that reach vulnerable functions.
        initial_objs (list, optional): List of source object node IDs. If provided,
            only solutions for these objects are returned. Defaults to None.
        contains (bool, optional): If True, model sink values as "contains" constraint
            (substring match). If False, use equality. Defaults to True.

    Yields:
        tuple: (assertions, results) where:
            - assertions: Z3 assertions (constraints) that were added to the solver
            - results: Either "failed" if unsat, or a dict mapping variable names to
              their concrete values (the exploit payload)

    Example:
        >>> # Solve for OS command injection exploit
        >>> G.solve_from = "; rm -rf /"  # Desired payload in sink
        >>> for assertions, results in solve2(G, [sink_obj], [source_obj]):
        ...     if results != "failed":
        ...         print("Exploit found:", results)
        ...         # results contains input values that produce the payload
    """
    time1 = time.time()
    print(
        "final objs:", final_objs, "value:", G.solve_from, "initial objs:", initial_objs
    )
    solver = None
    symbols = None

    def symbol(obj):
        """
        Get or create a Z3 symbol for an object node.

        Creates a MixedSymbol (with both string and numeric views) for the object,
        and adds constraints for its value if it's a literal (not wildcard).

        Args:
            obj: Object node ID

        Returns:
            MixedSymbol: The Z3 symbol representation of the object
        """
        nonlocal G, symbols, solver
        if obj not in symbols:
            t = G.get_node_attr(obj).get("type")
            v = G.get_node_attr(obj).get("code")
            # Create mixed symbol (supports both string and number operations)
            s = symbols[obj] = MixedSymbol(obj, t)
            
            # Add constraints for literal values (not wildcards)
            if v != wildcard:
                if t == "string":
                    if obj in final_objs and contains:
                        # For sink objects, use "contains" constraint (substring match)
                        # This allows finding inputs that produce the desired payload
                        solver.add(z3.Contains(s.string(), v))
                    else:
                        # For intermediate values, use equality constraint
                        solver.add(s.string() == z3.StringVal(v))
                elif t == "number":
                    # Numeric literals use equality
                    solver.add(s.number() == v)
        return symbols[obj]

    for final_obj in final_objs:
        # Temporarily modify the sink object to represent the desired exploit value
        # This allows the solver to work backward to find inputs that produce this value
        original_type = G.get_node_attr(final_obj).get("type")
        original_value = G.get_node_attr(final_obj).get("code")
        if type(G.solve_from) in [int, float]:
            G.set_node_attr(final_obj, ("type", "number"))
        elif type(G.solve_from) == str:
            G.set_node_attr(final_obj, ("type", "string"))
        G.set_node_attr(final_obj, ("code", G.solve_from))

        # Initialize Z3 solver and symbol cache for this sink object
        solver = z3.Solver()
        symbols = defaultdict(MixedSymbol)
        q = [final_obj]  # Queue for backward traversal
        
        # Create symbol for sink object (in case it's directly a function parameter)
        symbol(final_obj)

        # Backward traversal: follow CONTRIBUTES_TO edges to build constraint system
        # The algorithm works by:
        # 1. Starting from the sink object (final_obj)
        # 2. Finding all nodes that contribute to its value via CONTRIBUTES_TO edges
        # 3. Grouping contributors by operation (e.g., all operands of a concatenation)
        # 4. Adding Z3 constraints that model these operations
        # 5. Recursively processing contributor nodes until sources or literals are reached
        while q:
            head = q.pop(0)  # Current object we're building constraints for
            _contributors = []  # List of (operation_tag, contributor_node)
            contributors = defaultdict(list)  # Grouped by (operation, group_id)
            
            # Collect all contributors (nodes that contribute to this object's value)
            for e in G.get_in_edges(head, edge_type="CONTRIBUTES_TO"):
                opt = e[-1].get("opt")  # Operation tag: (op_name, group_id, operand_index)
                if opt is None:
                    continue
                # Add contributor to queue for processing
                if e[0] not in q:
                    q.append(e[0])
                _contributors.append((opt, e[0]))
            
            # Sort and group contributors by operation type and group ID
            # This groups operands that belong to the same operation together
            # e.g., for "a + b + c", a, b, and c will share the same group ID
            _contributors = sorted(_contributors)
            for opt, c in _contributors:
                contributors[(opt[0], opt[1])].append(c)
            
            # Convert each operation group into Z3 constraints
            for opt, cl in contributors.items():
                op_name = opt[0]  # Operation name (e.g., "string_concat", "numeric_add")
                
                if op_name == "string_concat":
                    # Model string concatenation: result = str1 + str2 + ...
                    # We check if all operands can be treated as strings
                    if check_string_operation(map(symbol, [head] + cl)):
                        cl_string_symbols = list(map(lambda x: symbol(x).string(), cl))
                        if len(cl_string_symbols) == 1:
                            # Single operand: direct assignment (result = operand)
                            solver.add(symbol(head).string() == cl_string_symbols[0])
                        else:
                            # Multiple operands: concatenation (result = op1 + op2 + ...)
                            solver.add(
                                symbol(head).string() == z3.Concat(*cl_string_symbols)
                            )
                    else:
                        print(f"ERROR: Checking {cl} for string_concat failed!")
                        
                elif op_name == "numeric_add":
                    # Model numeric addition: result = num1 + num2 + ...
                    # We check if all operands can be treated as numbers
                    if check_number_operation(map(symbol, [head] + cl)):
                        cl_number_symbols = list(map(lambda x: symbol(x).number(), cl))
                        if len(cl_number_symbols) == 1:
                            # Single operand: direct assignment (result = operand)
                            solver.add(symbol(head).number() == cl_number_symbols[0])
                        else:
                            # Multiple operands: sum (result = op1 + op2 + ...)
                            solver.add(
                                symbol(head).number() == reduce(add, cl_number_symbols)
                            )
                    else:
                        print(f"ERROR: Checking {cl} for numeric_add failed!")
                        
                elif op_name == "unknown_add":
                    # Operation type is unknown at analysis time - could be string or number
                    # This happens with the '+' operator in JS when types aren't statically known
                    # Try string first (more common for vulnerabilities like XSS/Command Injection)
                    if check_string_operation(map(symbol, [head] + cl)):
                        cl_string_symbols = list(map(lambda x: symbol(x).string(), cl))
                        if len(cl_string_symbols) == 1:
                            solver.add(symbol(head).string() == cl_string_symbols[0])
                        else:
                            solver.add(
                                symbol(head).string() == z3.Concat(*cl_string_symbols)
                            )
                    elif check_number_operation(map(symbol, [head] + cl)):
                        # Fall back to numeric addition if string model fails
                        cl_number_symbols = list(map(lambda x: symbol(x).number(), cl))
                        if len(cl_number_symbols) == 1:
                            solver.add(symbol(head).number() == cl_number_symbols[0])
                        else:
                            solver.add(
                                symbol(head).number() == reduce(add, cl_number_symbols)
                            )
                    else:
                        print(f"ERROR: Checking {cl} for unknown_add failed!")
                else:
                    # Unknown operation type - skip (could be extended in future)
                    pass

        # Apply extra constraints (e.g., sanitization checks, forbidden patterns)
        # These are constraints added during analysis to model security checks
        for targets, rule, literal in G.extra_constraints:
            for target in targets:
                if type(literal) == str:
                    sym = symbol(target).string()
                    if rule == "not-contains":
                        # Constraint: value must NOT contain this literal
                        # Used to model sanitization (e.g., no ";" in command)
                        if sym is not None:
                            solver.add(z3.Not(z3.Contains(sym, z3.StringVal(literal))))
                    elif rule == "contains":
                        # Constraint: value must contain this literal
                        # Used to model required patterns
                        if sym is not None:
                            solver.add(z3.Contains(sym, z3.StringVal(literal)))

        # Add security constraints to prevent certain dangerous patterns
        # These help ensure generated exploits are realistic
        # Note: Some constraints are commented out but could be re-enabled
        # solver.add(z3.Not(z3.PrefixOf(z3.StringVal('"'), symbol(final_obj).string())))
        
        # Prevent command chaining (semicolon) and HTML entity encoding (ampersand)
        # These are common sanitization patterns
        solver.add(z3.Not(z3.PrefixOf(z3.StringVal(";"), symbol(final_obj).string())))
        solver.add(z3.Not(z3.PrefixOf(z3.StringVal("&"), symbol(final_obj).string())))

        # Restore original object attributes
        G.set_node_attr(final_obj, ("type", original_type))
        G.set_node_attr(final_obj, ("code", original_value))
        
        # Set solver timeout (2 seconds) to prevent hanging on complex constraints
        solver.set(timeout=2000)
        path_results = {}
        
        try:
            # Check if constraints are satisfiable
            if solver.check() == z3.unsat:
                # Constraints are unsatisfiable - path is not feasible
                # This means no input values can produce the desired exploit
                yield solver.assertions(), "failed"
                continue
            
            # Get model (solution) - concrete values for all variables
            model = solver.model()
        except z3.Z3Exception:
            # Solver error (timeout, etc.) - treat as failed
            yield solver.assertions(), "failed"
            continue
        
        # Extract solution values for source objects (user inputs)
        for var in model:
            vn = str(var)  # Variable name (e.g., "s123" for string, "n456" for number)
            
            if vn in path_results:
                print("ERROR: duplicated variable" + vn)
            
            # Filter to only source objects if initial_objs is specified
            if initial_objs and vn[1:] not in initial_objs:
                continue
            
            # Map variable back to original variable names for readability
            # G.reverse_names maps object IDs to their variable names
            if G.reverse_names[vn[1:]]:
                name = ", ".join(G.reverse_names[vn[1:]])
                # Store: (human-readable name, concrete value from solver)
                path_results[vn] = (name, model[var])
            else:
                # No reverse mapping - skip (internal intermediate value)
                pass
        
        # Yield results: (constraints, exploit values)
        yield (solver.assertions(), path_results)
    G.solver_time += time.time() - time1


def solve1(G: Graph, final_objs, initial_objs=None, contains=True):
    results = []

    def get_symbol(obj):
        nonlocal G, symbol, solver
        if obj not in symbol:
            t = G.get_node_attr(obj).get("type")
            v = G.get_node_attr(obj).get("code")
            # print('type =', t, 'value =', v)
            if t == "number":
                symbol[obj] = z3.Real(f"n{obj}")
                solver.add(symbol[obj] == float(v))
            elif t == "string":
                symbol[obj] = z3.String(f"s{obj}")
                if obj in final_objs and contains:
                    solver.add(z3.Contains(symbol[obj], v))  # str contains
                    # solver.add(z3.InRe(symbol[obj], z3.Re(v))) # regex
                else:
                    solver.add(symbol[obj] == z3.StringVal(v))
            # elif v == wildcard or t == 'object':
            else:
                symbol[obj] = (z3.Real(f"n{obj}"), z3.String(f"s{obj}"))

    for final_obj in final_objs:
        original_type = G.get_node_attr(final_obj).get("type")
        original_value = G.get_node_attr(final_obj).get("code")
        if type(G.solve_from) in [int, float]:
            G.set_node_attr(final_obj, ("type", "number"))
        elif type(G.solve_from) == str:
            G.set_node_attr(final_obj, ("type", "string"))
        G.set_node_attr(final_obj, ("code", G.solve_from))
        symbol = {}
        solver = z3.Solver()

        q = [final_obj]
        get_symbol(final_obj)
        # visited_objs = set()
        while q:
            obj = q.pop(0)
            contributors = []
            in_edges = G.get_in_edges(obj, edge_type="CONTRIBUTES_TO")
            print(in_edges)
            for e in in_edges:
                op = e[-1].get("op", "")
                contributors.append((op, e[0]))
                if e[0] not in q:
                    q.append(e[0])
            contributors = sorted(contributors)
            for tag1, source1 in contributors:
                match = re.match(r"(\w+)#(\w+)", tag1)
                if not match:
                    continue
                op, order = match.groups()
                if order != "0":
                    continue
                get_symbol(source1)
                for tag2, source2 in contributors:
                    get_symbol(source2)
                    if tag2 == f"{op}#1":
                        if type(symbol[source1]) == tuple:
                            if type(symbol[source2]) == tuple:
                                if type(symbol[obj]) == tuple:
                                    if tag1.startswith(
                                        "numeric_add"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1][0] + symbol[source2][0]
                                            == symbol[obj][0]
                                        )
                                    if tag1.startswith(
                                        "string_concat"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1][1] + symbol[source2][1]
                                            == symbol[obj][1]
                                        )
                                elif type(symbol[obj]) == z3.ArithRef:
                                    if tag1.startswith(
                                        "numeric_add"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1][0] + symbol[source2][0]
                                            == symbol[obj]
                                        )
                                elif type(symbol[obj]) == z3.SeqRef:
                                    if tag1.startswith(
                                        "numeric_add"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1][1] + symbol[source2][1]
                                            == symbol[obj]
                                        )
                            elif type(symbol[source2]) == z3.ArithRef:
                                if type(symbol[obj]) == tuple:
                                    if tag1.startswith(
                                        "numeric_add"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1][0] + symbol[source2]
                                            == symbol[obj][0]
                                        )
                                elif type(symbol[obj]) == z3.ArithRef:
                                    if tag1.startswith(
                                        "numeric_add"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1][0] + symbol[source2]
                                            == symbol[obj]
                                        )
                            elif type(symbol[source2]) == z3.SeqRef:
                                if type(symbol[obj]) == tuple:
                                    if tag1.startswith(
                                        "string_concat"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1][1] + symbol[source2]
                                            == symbol[obj][1]
                                        )
                                elif type(symbol[obj]) == z3.SeqRef:
                                    if tag1.startswith(
                                        "string_concat"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1][1] + symbol[source2]
                                            == symbol[obj]
                                        )
                        elif type(symbol[source1]) == z3.ArithRef:
                            if type(symbol[source2]) == tuple:
                                if type(symbol[obj]) == tuple:
                                    if tag1.startswith(
                                        "numeric_add"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1] + symbol[source2][0]
                                            == symbol[obj][0]
                                        )
                                elif type(symbol[obj]) == z3.ArithRef:
                                    if tag1.startswith(
                                        "numeric_add"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1] + symbol[source2][0]
                                            == symbol[obj]
                                        )
                            elif type(symbol[source2]) == z3.ArithRef:
                                if type(symbol[obj]) == tuple:
                                    if tag1.startswith(
                                        "numeric_add"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1] + symbol[source2]
                                            == symbol[obj][0]
                                        )
                                elif type(symbol[obj]) == z3.ArithRef:
                                    if tag1.startswith(
                                        "numeric_add"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1] + symbol[source2]
                                            == symbol[obj]
                                        )
                        elif type(symbol[source1]) == z3.SeqRef:
                            if type(symbol[source2]) == tuple:
                                if type(symbol[obj]) == tuple:
                                    if tag1.startswith(
                                        "string_concat"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1] + symbol[source2][1]
                                            == symbol[obj][1]
                                        )
                                elif type(symbol[obj]) == z3.SeqRef:
                                    if tag1.startswith(
                                        "string_concat"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1] + symbol[source2][1]
                                            == symbol[obj]
                                        )
                            elif type(symbol[source2]) == z3.SeqRef:
                                if type(symbol[obj]) == tuple:
                                    if tag1.startswith(
                                        "string_concat"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1] + symbol[source2]
                                            == symbol[obj][1]
                                        )
                                elif type(symbol[obj]) == z3.SeqRef:
                                    if tag1.startswith(
                                        "string_concat"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1] + symbol[source2]
                                            == symbol[obj]
                                        )
                        break
        for targets, rule, literal in G.extra_constraints:
            for target in targets:
                if type(literal) == str:
                    get_symbol(target)
                    if type(symbol[target]) == tuple:
                        if rule == "not-contains":
                            solver.add(
                                z3.Not(
                                    z3.Contains(
                                        symbol[target][1], z3.StringVal(literal)
                                    )
                                )
                            )
                        elif rule == "contains":
                            solver.add(
                                z3.Contains(symbol[target][1], z3.StringVal(literal))
                            )
                        # elif rule == 'contains':
                    elif type(symbol[target]) == z3.SeqRef:
                        if rule == "not-contains":
                            solver.add(
                                z3.Not(
                                    z3.Contains(symbol[target], z3.StringVal(literal))
                                )
                            )
                        elif rule == "contains":
                            solver.add(
                                z3.Contains(symbol[target], z3.StringVal(literal))
                            )
        G.set_node_attr(final_obj, ("type", original_type))
        G.set_node_attr(final_obj, ("code", original_value))
        solver.set(timeout=30000)
        path_results = defaultdict(list)
        try:
            if solver.check() == z3.unsat:
                # print(solver.assertions())
                yield (solver.assertions(), "failed")
                continue
            model = solver.model()
        except z3.Z3Exception:
            yield (solver.assertions(), "failed")
            continue
        for var in model:
            vn = str(var)
            if initial_objs and vn[1:] not in initial_objs:
                continue
            # if vn[1:] in G.reverse_names:
            if G.reverse_names[vn[1:]]:
                name = ", ".join(G.reverse_names[vn[1:]]) + f"({vn})"
                path_results[name].append(model[var])
            else:
                # results[vn] = model[var]
                pass
        # results.append(solver.assertions(), path_results)
        yield (solver.assertions(), path_results or "timeout")
    # return results


solve = solve2
