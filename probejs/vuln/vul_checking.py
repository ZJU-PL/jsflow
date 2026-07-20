"""
This module is used to check the vulnerabilities of the code.
"""

import re

from ..core.trace_rule import TraceRule
from .vul_func_lists import *
from ..utils.helpers import get_func_name, is_wildcard_obj
from ..utils.utilities import wildcard


def get_path_text(G, path, caller):
    """
    get the code by ast number
    Args:
        G: the graph
        path: the path with ast nodes
    Return:
        str: a string with text path
    """
    res_path = ""
    cur_path_str1 = ""
    cur_path_str2 = ""
    for node in path:
        cur_node_attr = G.get_node_attr(node)
        if cur_node_attr.get("lineno:int") is None:
            continue
        if cur_node_attr.get("labels:label") in ["Artificial", "Artificial_AST"]:
            continue
        # if cur_node_attr.get('lineno:int') == '': # workaround?
        #     G.logger.error('No line number for node {} {}'.format(node, cur_node_attr))
        #     continue
        cur_path_str1 += cur_node_attr["lineno:int"] + "->"
        start_lineno = int(cur_node_attr["lineno:int"])
        end_lineno = int(cur_node_attr["endlineno:int"] or start_lineno)
        content = None
        try:
            content = G.get_node_file_content(node)
        except:
            pass
        if content is not None:
            # AST locations are one-based, while the source buffer is zero-based.
            # Generated CommonJS scaffolding can also span beyond the last original
            # TypeScript line, so keep reporting bounded to the owning source file.
            start_index = max(start_lineno - 1, 0)
            end_index = min(max(end_lineno, start_lineno), len(content))
            for l in range(start_index, end_index):
                if "function" in content[l]:
                    content = (
                        "".join(content[start_index : l + 1]).rstrip()
                        + " ... (omitted)\n"
                    )
                    break
            if type(content) is list:
                content = "".join(content[start_index:end_index])
            cur_path_str2 += "{}\t{}".format(start_lineno, content)
    cur_path_str1 += G.get_node_attr(caller).get("lineno:int", "?")
    G.logger.debug(cur_path_str1)

    res_path += "==========================\n"
    res_path += "{}\n".format(G.get_node_file_path(path[0]))
    res_path += cur_path_str2
    return res_path


def traceback(G, vul_type, start_node=None):
    """
    Trace back execution paths from vulnerability sinks to potential sources.

    This function identifies potential sink functions (based on the vulnerability type)
    and performs a backward traversal (DFS) on the graph to find all paths that reach
    these sinks via data flow (OBJ_REACHES edges).

    It serves as the first step in vulnerability detection by generating candidate
    paths that are subsequently filtered by `vul_checking` using specific rules.

    Args:
        G (Graph): The graph object containing the analysis results.
        vul_type (str): The type of vulnerability to check (e.g., 'xss', 'os_command').
            This determines which functions are considered sinks.
        start_node (str, optional): A specific starting node for the traceback.
            Defaults to None, which means all relevant sinks in the graph are checked.

    Returns:
        tuple: A tuple containing:
            - ret_pathes (list): List of candidate paths (lists of node IDs).
            - res_path (str): String representation of the paths (for logging).
            - caller_list (list): List of descriptions of the sink calls found.
    """

    def find_func_name(node):
        func = G.get_node_attr(node).get("funcid:int")
        if not func:
            while G.get_node_attr(node).get("type") not in [
                "AST_FUNC_DECL",
                "AST_CLOSURE",
                "AST_METHOD",
                "AST_TOPLEVEL",
            ]:
                node = G.get_in_edges(node, edge_type="PARENT_OF")[0][0]
            func = node
        # print('found node', node, 'in function', func, G.get_name_from_child(func))
        return G.get_name_from_child(func)

    res_path = ""
    expoit_func_list = signature_lists[vul_type]

    if G.new_trace_rule:
        func_nodes = G.get_node_by_attr("type", "DUMMY_STMT")
        # print('func nodes', func_nodes)
    else:
        func_nodes = G.get_node_by_attr("type", "AST_METHOD_CALL")
        func_nodes += G.get_node_by_attr("type", "AST_CALL")
        func_nodes += G.get_node_by_attr("type", "AST_NEW")
    ret_pathes = []
    caller_list = []

    def _get_old_call_names(node):
        node_attr = G.get_node_attr(node)
        names = []
        if node_attr.get("type") == "AST_METHOD_CALL":
            children = G.get_ordered_ast_child_nodes(node)
            if len(children) >= 2:
                receiver = G.get_name_from_child(children[0], order=1)
                method = G.get_name_from_child(children[1], order=1)
                if receiver and method:
                    names.append(f"{receiver}.{method}")
                if method:
                    names.append(method)
        fallback = G.get_name_from_child(node, order=1)
        if fallback:
            names.append(fallback)
        # preserve order but remove dups
        out = []
        for n in names:
            if n not in out:
                out.append(n)
        return out

    for func_node in func_nodes:
        # we assume only one obj_decl edge
        if G.new_trace_rule:
            func_name = find_func_name(func_node)
        else:
            func_names = _get_old_call_names(func_node)
            func_name = next((n for n in func_names if n in expoit_func_list), None)
        if func_name and func_name in expoit_func_list:
            caller = func_node
            caller = G.find_nearest_upper_CPG_node(caller)
            caller_list.append("{} called {}".format(caller, func_name))
            pathes = G._dfs_upper_by_edge_type(caller, "OBJ_REACHES")

            # here we treat the single calling as a possible path
            # pathes.append([caller])
            G.logger.debug("Paths:")

            # give the end node one more chance, find the parent obj of the ending point
            """
            for path in pathes:
                last_node = path[-1]
                upper_nodes = G._dfs_upper_by_edge_type(last_node, 
                        "OBJ_TO_PROP")
                for uppernode in upper_nodes:
                    path.append(uppernode)
                #print('--', upper_nodes)
            """
            for path in pathes:
                ordered_path = list(reversed(path))
                ret_pathes.append(ordered_path)
                res_path += get_path_text(G, ordered_path, caller)
    return ret_pathes, res_path, caller_list


def do_vul_checking(G, rule_list, pathes):
    """
    Check paths against a list of trace rules to identify vulnerabilities.

    This function applies a list of trace rules to candidate paths. A path
    is considered vulnerable if it satisfies ALL rules in the rule_list.
    Each rule is a tuple of (rule_function_name, rule_arguments).

    The function works by:
    1. Creating TraceRule objects for each rule in the rule_list
    2. For each candidate path, checking all rules in sequence
    3. If any rule fails, the path is rejected
    4. Only paths that pass all rules are returned

    Common rule types:
    - 'has_user_input': Checks if path contains tainted user input
    - 'not_exist_func': Checks that specified functions don't appear in path
    - 'exist_func': Checks that specified functions appear in path
    - 'end_with_func': Checks that path ends at a specific function call
    - 'start_with_func': Checks that path starts at a specific function
    - 'start_within_file': Checks that path starts in a specific file
    - 'not_start_within_file': Checks that path doesn't start in specific files

    Args:
        G (Graph): The graph object containing the analysis results
        rule_list (list): List of rule tuples. Each tuple contains:
            - rule_function_name (str): Name of the trace rule function.
              Must match a method name in TraceRule class.
            - rule_arguments: Arguments for the rule function. Can be:
              - None: No arguments needed
              - list: List of function names, file names, or variable names
              - Other types as required by specific rules
        pathes (list): List of candidate paths to check. Each path is a
            list of node IDs representing an execution path through the graph.

    Returns:
        list: List of paths that satisfy all rules in rule_list. Each path
            is a list of node IDs. Empty list if no paths satisfy all rules.

    Example:
        >>> # Check for OS command injection: user input reaching exec without sanitization
        >>> rule_list = [
        ...     ('has_user_input', None),  # Path must contain user input
        ...     ('not_exist_func', ['parseInt']),  # No parseInt sanitization
        ...     ('end_with_func', ['sink_hqbpillvul_exec'])  # Ends at exec()
        ... ]
        >>> vulnerable = do_vul_checking(G, rule_list, candidate_paths)
        >>> # Check for XSS: user input reaching HTTP write without sanitization
        >>> xss_rules = [
        ...     ('has_user_input', None),
        ...     ('not_exist_func', ['parseInt']),
        ...     ('end_with_func', ['sink_hqbpillvul_http_write'])
        ... ]
        >>> xss_paths = do_vul_checking(G, xss_rules, paths)
    """
    trace_rules = []
    for rule in rule_list:
        trace_rules.append(TraceRule(rule[0], rule[1], G))

    success_pathes = []
    for path in pathes:
        flag = True
        for trace_rule in trace_rules:
            if not trace_rule.check(path):
                flag = False
                break
        if flag:
            success_pathes.append(path)
    return success_pathes


def _evaluate_rule_list(G, rule_list, path):
    """Evaluate a single rule list against a path and keep per-rule diagnostics."""
    trace_rules = [TraceRule(rule[0], rule[1], G) for rule in rule_list]
    evaluations = []
    matched = True
    for trace_rule in trace_rules:
        result = trace_rule.evaluate(path)
        evaluations.append(result)
        if not result["passed"]:
            matched = False
            break
    return matched, evaluations


def vul_checking(G, pathes, vul_type, return_diagnostics=False):
    """
    Filter paths to identify those that satisfy vulnerability detection rules.

    This function applies vulnerability-specific trace rules to candidate paths
    and returns only those paths that match the vulnerability pattern. Different
    vulnerability types have different rule sets that check for:
    - Presence of user input (source)
    - Absence of sanitization functions
    - Presence of vulnerable sink functions
    - Path characteristics specific to each vulnerability type

    The function uses a rule-based approach where each vulnerability type has
    one or more rule lists. A path is considered vulnerable if it satisfies
    ALL rules in at least one rule list. This allows for multiple patterns
    to be detected for the same vulnerability type.

    Rule evaluation:
    - Rules are applied in order within each rule list
    - All rules in a list must pass for the path to be vulnerable
    - If any rule fails, the next rule list is tried
    - A path is added to results if it satisfies any complete rule list

    Args:
        G (Graph): The graph object containing the analysis results
        pathes (list): List of candidate paths (sequences of node IDs) to check.
            Each path represents a potential data flow from source to sink.
        vul_type (str): Type of vulnerability to check. Must be one of:
            - 'xss': Cross-site scripting - checks for unsanitized user input
              reaching HTTP response writing functions
            - 'os_command': OS command injection - checks for user input reaching
              command execution functions (exec, spawn, etc.)
            - 'code_exec': Code execution vulnerabilities - checks for user input
              reaching eval(), Function(), or command execution
            - 'proto_pollution': Prototype pollution - checks for tainted property
              names being assigned to prototype chains
            - 'path_traversal': Path traversal - checks for URL parameters reaching
              file system operations without sanitization
            - 'nosql': NoSQL injection - checks for user input reaching MongoDB
              query functions without sanitization

    Returns:
        list: List of paths that satisfy the vulnerability detection rules.
            Each path is a list of node IDs representing the vulnerable execution
            path from source to sink. Empty list if no vulnerable paths found.

    Example:
        >>> from probejs.vul_checking import vul_checking
        >>> # Check for XSS vulnerabilities
        >>> vulnerable_paths = vul_checking(G, candidate_paths, 'xss')
        >>> print(f"Found {len(vulnerable_paths)} XSS vulnerabilities")
        >>> # Check for OS command injection
        >>> cmd_paths = vul_checking(G, paths, 'os_command')
    """
    # Vulnerability-specific sanitizer heuristics.
    #
    # Note: This project is intentionally lightweight/heuristic in places.
    # These lists exist to keep regression tests stable while we improve
    # precision of the underlying analysis.
    xss_sanitizers = signature_lists["sanitation"] + ["escapeHtml"]
    os_command_sanitizers = signature_lists["sanitation"] + ["has"]
    path_traversal_sanitizers = signature_lists["sanitation"] + [
        "normalize",
        "join",
        "startsWith",
    ]

    xss_rule_lists = [
        [
            ("has_user_input", None),
            ("not_start_with_func", ["sink_hqbpillvul_http_write"]),
            ("not_exist_func", xss_sanitizers),
            ("end_with_func", ["sink_hqbpillvul_http_write"]),
        ],
        [
            ("has_user_input", None),
            ("not_start_with_func", ["sink_hqbpillvul_http_setHeader"]),
            ("not_exist_func", xss_sanitizers),
            ("end_with_func", ["sink_hqbpillvul_http_setHeader"]),
        ],
        # Express-style response sinks (often appear as dummy functions).
        [
            ("has_user_input", None),
            ("not_start_with_func", ["res.send"]),
            ("not_exist_func", xss_sanitizers),
            ("end_with_func", ["res.send"]),
        ],
    ]
    os_command_rule_lists = [
        [
            ("has_user_input", None),
            ("not_start_within_file", ["child_process.js"]),
            ("not_exist_func", os_command_sanitizers),
            (
                "exist_func",
                signature_lists["os_command"]
                + [
                    "child_process.exec",
                    "child_process.execFile",
                    "child_process.execSync",
                    "child_process.spawn",
                    "child_process.spawnSync",
                ],
            ),
        ]
    ]

    code_exec_lists = [
        [
            ("has_user_input", None),
            ("not_start_within_file", ["eval.js"]),
            ("not_exist_func", ["parseInt"]),
        ],
        [
            ("has_user_input", None),
            ("end_with_func", ["Function"]),
            ("not_exist_func", ["parseInt"]),
        ],
        [
            ("has_user_input", None),
            ("end_with_func", ["eval"]),
            ("not_exist_func", ["parseInt"]),
        ],
        # include os command here
        [
            ("has_user_input", None),
            ("not_start_within_file", ["child_process.js"]),
            ("not_exist_func", ["parseInt"]),
        ],
    ]
    proto_pollution = [
        [("has_user_input", None), ("not_exist_func", signature_lists["sanitation"])]
    ]
    path_traversal = [
        # Direct fs reads in application code.
        [
            ("has_user_input", None),
            ("not_exist_func", path_traversal_sanitizers),
            ("end_with_func", ["fs.readFile", "fs.readFileSync"]),
        ],
        [
            ("has_user_input", None),
            # Avoid flagging flows that only exist inside the built-in `fs.js` stub;
            # prefer detecting at the application callsite (rule list above).
            ("not_start_within_file", ["fs.js"]),
            ("not_exist_func", path_traversal_sanitizers),
            ("end_with_func", signature_lists["path_traversal"]),
            ("exist_func", ["sink_hqbpillvul_fs_read"]),
            # ('exist_func', ['__opgCombine'])
        ],
        [
            ("has_user_input", None),
            ("not_exist_func", path_traversal_sanitizers),
            ("end_with_func", ["sink_hqbpillvul_http_sendFile"]),
        ],
    ]
    nosql_rule_lists = [
        [
            ("has_user_input", None),
            ("not_start_within_file", ["mongodb.js", "monk.js"]),
            ("not_exist_func", signature_lists["sanitation"]),
            ("exist_func", signature_lists["nosql"]),
        ]
    ]

    vul_type_map = {
        "xss": xss_rule_lists,
        "os_command": os_command_rule_lists,
        "code_exec": code_exec_lists,
        "proto_pollution": proto_pollution,
        "path_traversal": path_traversal,
        "nosql": nosql_rule_lists,
    }

    rule_lists = vul_type_map[vul_type]
    success_paths = []
    diagnostics = []
    print("vul_checking", vul_type)
    """
    print(pathes)
    for path in pathes:
        for node in path:
            print(G.get_node_attr(node))
    """
    for path in pathes:
        path_diagnostic = {
            "path": list(path),
            "matched": False,
            "matched_rule_list": None,
            "rule_lists": [],
        }
        for index, rule_list in enumerate(rule_lists):
            matched, evaluations = _evaluate_rule_list(G, rule_list, path)
            path_diagnostic["rule_lists"].append(
                {
                    "rule_list_index": index,
                    "matched": matched,
                    "rules": evaluations,
                    "first_failed_rule": next(
                        (rule["name"] for rule in evaluations if not rule["passed"]),
                        None,
                    ),
                }
            )
            if matched and not path_diagnostic["matched"]:
                path_diagnostic["matched"] = True
                path_diagnostic["matched_rule_list"] = index
                success_paths.append(path)
        diagnostics.append(path_diagnostic)

    print("success: ", success_paths)
    if return_diagnostics:
        return success_paths, diagnostics
    return success_paths


def check_pp(G):
    """
    Detect prototype pollution patterns.

    This checker is intentionally heuristic: prototype pollution often happens
    through "deep set"/"deep merge" helpers instead of explicit writes to
    `Object.prototype`.

    We look for:
    - Direct writes to dangerous keys (`__proto__`, `prototype`, `constructor`)
      where key/value is influenced by user input.
    - Writes to built-in prototypes (Object/String/Array/Function/...) with
      user-controlled property names.
    - Calls to merge/set-like helpers where attacker-controlled objects/paths
      can introduce dangerous keys.
    """
    print("Checking proto_pollution...")

    DANGEROUS_KEYS = {"__proto__", "prototype", "constructor"}

    # Common helper names that can lead to prototype pollution when fed an
    # attacker-controlled object or property path.
    #
    # Note: We intentionally include both bare names and common qualified names
    # (e.g. Object.assign, _.merge) because ProbeJS often loses module/receiver
    # identity in graphs.
    MERGE_LIKE_FUNCS = {
        "merge",
        "mergewith",
        "mergeWith",
        "deepmerge",
        "deepMerge",
        "extend",
        "extendwith",
        "extendWith",
        "assign",
        "assignin",
        "assignIn",
        "defaultsdeep",
        "defaultsDeep",
        "defaults",
        "Object.assign",
        "object.assign",
        "_.merge",
        "_.mergeWith",
        "_.defaultsDeep",
        "_.assign",
        "lodash.merge",
        "lodash.mergeWith",
        "lodash.defaultsDeep",
        "$.extend",
        "jquery.extend",
        "jQuery.extend",
        "jQuery.fn.extend",
    }
    SET_LIKE_FUNCS = {
        "set",
        "setwith",
        "setWith",
        "merge.set",
        "baseSet",
        "baseset",
        "put",
        "putil.set",
        "dot-prop.set",
        "dotprop.set",
        "object-path.set",
        "objectpath.set",
        "lodash.set",
        "_.set",
        # Common vulnerable helpers (e.g. arr-flatten-unflatten).
        "unflatten",
        "arr-unflatten",
        "arr-flatten-unflatten",
    }

    MERGE_LIKE_FUNCS_LOWER = {m.lower() for m in MERGE_LIKE_FUNCS}
    SET_LIKE_FUNCS_LOWER = {s.lower() for s in SET_LIKE_FUNCS}

    def _get_children(node_id, edge_type=None, child_type=None, child_label=None, edge_scope=None):
        children, scopes = [], []
        edges = G.get_out_edges(node_id, edge_type=edge_type)
        for edge in edges:
            aim = edge[1]
            aim_node_attr = G.get_node_attr(aim)
            aim_edge_scope = edge[-1].get("scope")
            if child_type is not None and aim_node_attr.get("type") != child_type:
                continue
            if child_label is not None and aim_node_attr.get("labels:label") != child_label:
                continue
            if edge_scope is not None and aim_edge_scope != edge_scope:
                continue
            children.append(aim)
            scopes.append(aim_edge_scope)
        return children, scopes

    def _is_tainted_obj(obj_node) -> bool:
        return bool(G.get_node_attr(obj_node).get("tainted"))

    def _is_wildcard_or_tainted(obj_node) -> bool:
        return _is_tainted_obj(obj_node) or is_wildcard_obj(G, obj_node)

    def _is_wildcard_or_tainted_string(obj_node) -> bool:
        """
        Property keys are usually strings; treat wildcard strings as attacker-controlled.
        Avoid counting wildcard numbers (array indices) as controlled keys.
        """
        attrs = G.get_node_attr(obj_node)
        if _is_tainted_obj(obj_node):
            return True
        if not is_wildcard_obj(G, obj_node):
            return False
        t = attrs.get("type")
        return t == "string" or t == wildcard

    def _obj_to_string(obj_node):
        """
        Best-effort extraction of a string value for an Object node.
        """
        attrs = G.get_node_attr(obj_node)
        v = attrs.get("value")
        if v is None:
            v = attrs.get("code")
        if v is None:
            v = attrs.get("name")
        if v is None:
            return None
        if v == wildcard:
            return None
        s = str(v).strip()
        # strip quotes if present
        if len(s) >= 2 and ((s[0] == s[-1] == "'") or (s[0] == s[-1] == '"')):
            s = s[1:-1]
        return s

    def _expr_obj_nodes(expr_ast, scope):
        obj_nodes, _ = _get_children(expr_ast, edge_type="REFERS_TO", child_label="Object", edge_scope=scope)
        return obj_nodes

    def _expr_is_tainted(expr_ast, scope) -> bool:
        return any(_is_tainted_obj(o) for o in _expr_obj_nodes(expr_ast, scope))

    def _expr_is_tainted_or_wildcard_string(expr_ast, scope) -> bool:
        return any(_is_wildcard_or_tainted_string(o) for o in _expr_obj_nodes(expr_ast, scope))

    def _string_has_dangerous_key_segment(s: str) -> bool:
        """
        Detect dangerous keys not only as a full key, but inside dotted / bracketed paths.
        Examples:
          "__proto__"
          "__proto__.polluted"
          "constructor.prototype.polluted"
          "a['__proto__'].b"
        """
        if not s:
            return False
        lower = s.lower()
        if "__proto__" in lower:
            return True
        if "constructor" in lower and "prototype" in lower:
            return True
        # Tokenize on non-identifier chars to catch bracket/dot variants.
        for tok in re.split(r"[^a-zA-Z0-9_$]+", lower):
            if tok in DANGEROUS_KEYS:
                return True
        return False

    def _expr_has_dangerous_literal(expr_ast, scope) -> bool:
        """
        Best-effort: if we can resolve a literal string value for the expression,
        check whether it is a dangerous key.
        """
        for o in _expr_obj_nodes(expr_ast, scope):
            s = _obj_to_string(o)
            if s is None:
                continue
            if s in DANGEROUS_KEYS:
                return True
            if _string_has_dangerous_key_segment(s):
                return True
        # Fallback to AST code if available (e.g. '"__proto__"')
        code = G.get_node_attr(expr_ast).get("code")
        if isinstance(code, str):
            c = code.strip().strip("'\"")
            if c in DANGEROUS_KEYS or _string_has_dangerous_key_segment(c):
                return True
        return False

    def _call_names(call_ast):
        """
        Return a small set of possible call names for matching:
        - receiver.method
        - method
        - fallback name
        """
        node_attr = G.get_node_attr(call_ast)
        names = []
        if node_attr.get("type") == "AST_METHOD_CALL":
            children = G.get_ordered_ast_child_nodes(call_ast)
            if len(children) >= 2:
                receiver = G.get_name_from_child(children[0], order=1)
                method = G.get_name_from_child(children[1], order=1)
                if receiver and method:
                    names.append(f"{receiver}.{method}")
                if method:
                    names.append(method)
        fallback = G.get_name_from_child(call_ast, order=1)
        if fallback:
            names.append(fallback)
        # preserve order but remove duplicates
        out = []
        for n in names:
            if n not in out:
                out.append(n)
        return out

    def _name_looks_merge_like(name: str) -> bool:
        n = name.lower()
        if n in MERGE_LIKE_FUNCS_LOWER:
            return True
        # Heuristic fallbacks for library-internal helpers (e.g. lodash baseMerge).
        return any(tok in n for tok in ("merge", "extend", "assign", "defaultsdeep"))

    def _name_looks_set_like(name: str) -> bool:
        n = name.lower()
        if n in SET_LIKE_FUNCS_LOWER:
            return True
        # Avoid matching unrelated words like "asset" by requiring a boundary-ish context.
        if "unflatten" in n:
            return True
        if n.endswith("set") or n.endswith(".set") or n.endswith("_set"):
            return True
        return any(tok in n for tok in ("object-path", "dot-prop", "putil", "setobject", "set-object"))

    def _receiver_looks_pollutable(prop_expr_ast, scope) -> bool:
        """
        Heuristic: identify writes that target built-in prototypes / their properties.
        """
        # Old approach: REFERS_TO Name nodes intersecting known pollutable names.
        name_nodes, _ = _get_children(prop_expr_ast, edge_type="REFERS_TO", child_label="Name", edge_scope=scope)
        if set(name_nodes) & set(getattr(G, "pollutable_name_nodes", set())):
            return True
        # Also consider receiver objects being known pollutable objects.
        try:
            receiver_ast = G.get_ordered_ast_child_nodes(prop_expr_ast)[0]
        except Exception:
            return False
        recv_objs = _expr_obj_nodes(receiver_ast, scope)
        if set(recv_objs) & set(getattr(G, "pollutable_objs", set())):
            return True
        return False

    results = set()

    # 1) Direct assignment patterns: x[ key ] = value / x.key = value
    for assign in G.get_node_by_attr("type", "AST_ASSIGN"):
        children = G.get_ordered_ast_child_nodes(assign)
        if len(children) < 2:
            continue
        left, right = children[:2]
        if G.get_node_attr(left).get("type") not in ["AST_DIM", "AST_PROP"]:
            continue

        # Determine scopes in which the left side is resolved
        _, scopes = _get_children(left, edge_type="REFERS_TO", child_label="Name")
        # Some AST nodes don't carry REFERS_TO edges directly; in that case, fall back
        # to a scope-agnostic check to avoid missing common patterns like `result[key]=...`.
        for scope in (set(scopes) or {None}):
            prop_children = G.get_ordered_ast_child_nodes(left)
            if len(prop_children) < 2:
                continue
            prop_name_ast = prop_children[1]

            # In real-world PP, the dangerous key often comes from iterating attacker-controlled objects.
            # ProbeJS frequently models such keys as wildcard strings rather than explicitly tainted.
            key_tainted = _expr_is_tainted_or_wildcard_string(prop_name_ast, scope)
            key_dangerous_literal = _expr_has_dangerous_literal(prop_name_ast, scope)
            value_tainted = _expr_is_tainted(right, scope)

            receiver_pollutable = _receiver_looks_pollutable(left, scope)

            # Production-oriented: require attacker influence AND a write pattern
            # that can realistically hit prototype gadgets.
            #
            # - If the key is tainted, it may be "__proto__"/"constructor"/"prototype",
            #   so writing to *any* object is potentially polluting (e.g. obj["__proto__"]).
            # - If the key is an explicit dangerous literal, require tainted value
            #   (to avoid flagging intentional hardcoded prototype plumbing).
            # - If the receiver is a known built-in prototype, require tainted key/value.
            if key_tainted:
                pass  # allow: obj[taintedKey] = ...
            elif key_dangerous_literal:
                if not value_tainted:
                    continue
            elif receiver_pollutable:
                if not (key_tainted or value_tainted):
                    continue
            else:
                continue

            # Record finding with a small reason tag for debugging/reporting.
            reason = []
            if key_tainted:
                reason.append("tainted_key")
            if value_tainted:
                reason.append("tainted_value")
            if key_dangerous_literal:
                reason.append("dangerous_key")
            if receiver_pollutable:
                reason.append("pollutable_receiver")
            G.set_node_attr(assign, ("pp_reason", ",".join(reason)))
            results.add(assign)

    # 2) Call patterns: merge/set helpers with attacker-controlled input
    call_nodes = G.get_node_by_attr("type", "AST_CALL") + G.get_node_by_attr("type", "AST_METHOD_CALL")
    for call in call_nodes:
        # Get ordered AST children and locate argument list node (best-effort)
        children = G.get_ordered_ast_child_nodes(call)
        if not children:
            continue

        # Determine likely call name(s)
        names = _call_names(call)
        # Also add helper get_func_name (often returns method only)
        fn = get_func_name(G, call)
        if fn and fn not in names:
            names.append(fn)

        lowered = {n.lower() for n in names if isinstance(n, str)}
        is_merge_like = any(_name_looks_merge_like(n) for n in lowered)
        is_set_like = any(_name_looks_set_like(n) for n in lowered)
        if not (is_merge_like or is_set_like):
            continue

        # Identify scopes for this call site (via any REFERS_TO edge)
        _, scopes = _get_children(call, edge_type="REFERS_TO")
        if not scopes:
            scopes = [None]

        for scope in set(scopes):
            # Argument list is usually the last child for calls in this AST format.
            arg_list_ast = children[-1] if children else None
            arg_asts = G.get_ordered_ast_child_nodes(arg_list_ast) if arg_list_ast else []

            # Determine whether any argument is wildcard/tainted object-ish.
            arg_obj_nodes = []
            for a in arg_asts:
                arg_obj_nodes.extend(_expr_obj_nodes(a, scope))

            any_tainted_arg_obj = any(_is_wildcard_or_tainted(o) for o in arg_obj_nodes)

            # Additionally, check for dangerous literal keys in string/path arguments.
            any_dangerous_key_arg = any(_expr_has_dangerous_literal(a, scope) for a in arg_asts)
            any_tainted_key_arg = any(_expr_is_tainted_or_wildcard_string(a, scope) for a in arg_asts)

            # Merge-like: flag when attacker-controlled object is merged/extended/assigned.
            if is_merge_like and any_tainted_arg_obj:
                reason = ["merge_like", "tainted_arg"]
                if any_dangerous_key_arg:
                    reason.append("dangerous_key_arg")
                if any_tainted_key_arg:
                    reason.append("tainted_key_arg")
                G.set_node_attr(call, ("pp_reason", ",".join(reason)))
                results.add(call)

            # Set-like: flag when key/path is attacker-controlled or explicitly dangerous.
            if is_set_like and (any_tainted_key_arg or any_dangerous_key_arg):
                reason = ["set_like"]
                if any_tainted_key_arg:
                    reason.append("tainted_key_arg")
                if any_dangerous_key_arg:
                    reason.append("dangerous_key_arg")
                if any_tainted_arg_obj:
                    reason.append("tainted_arg")
                G.set_node_attr(call, ("pp_reason", ",".join(reason)))
                results.add(call)

    # 3) Structural patterns: for-in loops copying properties to objects
    #
    # Many real-world PP gadgets look like:
    #   for (k in src) dst[k] = src[k]   (or recursive variants)
    # even when ProbeJS does not precisely taint `k`.
    #
    # We conservatively flag computed writes inside JS_FOR_IN loops, and
    # specifically detect the common "copy by loop key" pattern.
    def _ast_is_string_literal(ast_id) -> bool:
        code = G.get_node_attr(ast_id).get("code")
        if not isinstance(code, str):
            return False
        c = code.strip()
        return len(c) >= 2 and ((c[0] == c[-1] == "'") or (c[0] == c[-1] == '"'))

    for foreach in G.get_node_by_attr("type", "AST_FOREACH"):
        if G.get_node_attr(foreach).get("flags:string[]") != "JS_FOR_IN":
            continue
        try:
            src_obj_ast, _value_ast, key_ast, body_ast = G.get_ordered_ast_child_nodes(foreach)
        except Exception:
            continue

        key_name = G.get_name_from_child(key_ast, order=1) or G.get_name_from_child(key_ast)
        body_nodes = set([body_ast])
        try:
            body_nodes.update(G.get_all_child_nodes(body_ast))
        except Exception:
            pass

        for assign in (n for n in body_nodes if G.get_node_attr(n).get("type") == "AST_ASSIGN"):
            try:
                left, right = G.get_ordered_ast_child_nodes(assign)[:2]
            except Exception:
                continue
            if G.get_node_attr(left).get("type") != "AST_DIM":
                continue
            try:
                dim_children = G.get_ordered_ast_child_nodes(left)
                if len(dim_children) < 2:
                    continue
                prop_ast = dim_children[1]
            except Exception:
                continue

            prop_code = G.get_node_attr(prop_ast).get("code")
            prop_name = G.get_name_from_child(prop_ast, order=1) or G.get_name_from_child(prop_ast)

            # Most common PP copy pattern: dst[key] = ...
            if key_name and prop_name == key_name:
                G.set_node_attr(assign, ("pp_reason", "for_in_copy_key"))
                results.add(assign)
                continue

            # Also flag other computed writes inside for-in loops when the key isn't
            # a simple string literal (e.g. curr[prop] where prop is derived from the loop key).
            if not _ast_is_string_literal(prop_ast):
                # If we can *also* see dangerous path segments in the RHS, bump confidence.
                rhs_code = G.get_node_attr(right).get("code")
                if isinstance(rhs_code, str) and _string_has_dangerous_key_segment(rhs_code):
                    G.set_node_attr(assign, ("pp_reason", "for_in_computed_key_rhs_danger"))
                    results.add(assign)
                else:
                    G.set_node_attr(assign, ("pp_reason", "for_in_computed_key"))
                    results.add(assign)

    if results:
        print("found:", results)
    else:
        print("not found")
    return results
