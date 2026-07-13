"""
Trace Rule Definitions - Pattern matching rules for vulnerability path validation.

This module provides a rule-based system for validating and filtering candidate
vulnerability paths. After the analysis generates candidate paths from sources
to sinks, trace rules are applied to determine which paths represent actual
vulnerabilities.

Rule System Overview:
--------------------
Each trace rule checks a specific property of a path:
- Source validation: Does the path start from user input? (has_user_input)
- Sink validation: Does the path end at a dangerous function? (end_with_func)
- Sanitization checks: Does the path include sanitization? (not_exist_func)
- File filtering: Should certain files be excluded? (start_within_file)

Available Rules:
---------------
- has_user_input: Path must contain user-controlled data
- exist_func: Path must include specified function(s)
- not_exist_func: Path must NOT include specified function(s) (for sanitizers)
- start_with_func: Path must begin at specified function
- not_start_with_func: Path must NOT begin at specified function
- end_with_func: Path must end at specified function (sink)
- start_within_file: Path must originate in specified file(s)
- not_start_within_file: Path must NOT originate in specified file(s)

Implementation Versions:
-----------------------
- TraceRuleNew: Uses function scope tracking (funcid attribute)
- TraceRuleOld: Uses call node iteration (for compatibility)

The Graph.new_trace_rule flag determines which implementation is used.
"""


class TraceRuleInterface:
    """Base interface to keep rule implementations aligned."""

    def __init__(self, key, value, G):
        pass

    def check(self, path):
        pass


class TraceRuleNew(TraceRuleInterface):
    """
    a rule container, which include a rule and a related checking function
    """

    def __init__(self, key, value, G):
        self.key = key
        self.value = value
        self.graph = G

    def find_func_name(self, node):
        func = self.graph.get_node_attr(node).get("funcid:int")
        if not func:
            while True:
                print(
                    "goes to",
                    node,
                    self.graph.get_node_attr(node),
                    self.graph.get_in_edges(node, edge_type="PARENT_OF"),
                )
                if self.graph.get_node_attr(node).get("type") in [
                    "AST_FUNC_DECL",
                    "AST_CLOSURE",
                    "AST_METHOD",
                    "AST_TOPLEVEL",
                ]:
                    func = node
                    break
                edges = self.graph.get_in_edges(node, edge_type="PARENT_OF")
                if edges:
                    node = self.graph.get_in_edges(node, edge_type="PARENT_OF")[0][0]
                else:
                    func = None
                    break
        # print('found node', node, 'in function', func, self.graph.get_name_from_child(func))
        return self.graph.get_name_from_child(func) if func is not None else None

    def exist_func(self, func_names, path):
        """
        check whether in the path, all functions within {func_names} exists

        Args:
            func_names: a list of function names that need to appear in the path
            path: the path need to be checked

        Returns:
            checking result
        """
        called_func_list = set()
        for node in path:
            called_func_list.add(self.find_func_name(node))

        # print("@@@@@@@@ CALLED FUNCTIONS", called_func_list)

        for called_func_name in called_func_list:
            if called_func_name in func_names:
                return True

        return False

    def not_exist_func(self, func_names, path):
        """
        check if there exist a function named func_names in the path
        """
        return not self.exist_func(func_names, path)

    def start_with_func(self, func_names, path):
        """
        check whether a path starts with a function

        Args:
            func_names: the possible function names
            path: the path needed to be checked
        Return:
            True or False
        """
        start_node = path[0]
        cur_func = self.find_func_name(start_node)
        return cur_func in func_names

    def not_start_with_func(self, func_names, path):
        """
        check whether a path starts with a function

        Args:
            func_names: the possible function names
            path: the path needed to be checked
        Return:
            True or False
        """
        return not self.start_with_func(func_names, path)

    def not_start_within_file(self, file_names, path):
        """
        check whether a path starts within a file
        Args:
            file_names: the possible file names
            path: the path to be checked
        Return:
            True or False
        """
        start_node = path[0]
        return not self.start_within_file(file_names, path)

    def end_with_func(self, func_names, path):
        """
        check whether a path ends with a function

        Args:
            func_names: the possible function names
            path: the path needed to be checked
        Return:
            True or False
        """
        end_node = path[-1]
        cur_func = self.find_func_name(end_node)
        return cur_func in func_names

    def start_within_file(self, file_names, path):
        """
        check whether a path starts within a file
        Args:
            file_names: the possible file names
            path: the path to be checked
        Return:
            True or False
        """
        start_node = path[0]

        file_path = self.graph.get_node_file_path(start_node)
        if file_path is None:
            return False
        file_base = file_path if "/" not in file_path else file_path.split("/")[-1]
        return file_path in file_names or file_base in file_names

    def start_with_var(self, var_names, path):
        # TODO: not finished, need to update the var name finding algorithm
        """
        check whether a path starts with a variable
        Args:
            var_names: the possible var names
            path: the path to be checked
        Return:
            True or False
        """
        start_node = path[0]

        path_start_var_name = self.graph.get_name_from_child(start_node)
        cur_node = self.graph.get_node_attr(start_node)
        if path_start_var_name is None:
            return False
        return path_start_var_name in var_names

    def has_user_input(self, _, path):
        """
        check if any node in this path contains user input
        user input is defined as in the http, process or
        the arguments of the module entrance functions

        we check by the obj in the edges
        Args:
            path: the path
        Return:
            True or False
        """
        pre_node = None
        for node in path:
            node_name = self.graph.get_name_from_child(node)
            if node_name and node_name.startswith("OPGen_TAINTED_VAR"):
                return True
            if not pre_node:
                pre_node = node
                continue

            cur_edges = self.graph.get_edge_attr(pre_node, node)
            # print("{} --{}--> {}".format(pre_node, cur_edges, node))
            if not cur_edges:
                continue
            for k in cur_edges:
                if (
                    "type:TYPE" in cur_edges[k]
                    and cur_edges[k]["type:TYPE"] == "OBJ_REACHES"
                ):
                    obj = cur_edges[k]["obj"]
                    obj_attr = self.graph.get_node_attr(obj)
                    if "tainted" in obj_attr and obj_attr["tainted"]:
                        return True
                    # Check if the object is related to user input even if not explicitly marked as tainted in a simple way
                    # For example, check if it comes from known sources like 'req', 'process.argv', etc.
                    # This is a heuristic and might need adjustment.
            pre_node = node

            """
            all_child = self.graph.get_all_child_nodes(node)
            objs = []
            for child in all_child:
                objs += self.graph.get_in_edges(child, edge_type='OBJ_TO_AST')
            for obj in objs:
                node_attr = self.graph.get_node_attr(obj[0])
                # here we only keep the obj which in the OBJ_REACHES edges
                if 'tainted' in node_attr and node_attr['tainted']:
                    print(obj[0], node_attr, self.graph.get_node_attr(obj[1]))
                    return True
            """
        if self.start_within_file(["http.js", "process.js", "yargs.js"], path):
            return True
        return False

    def check(self, path):
        """
        select the checking function and run it based on the key value
        Return:
            the running result of the obj
        """
        key_map = {
            "exist_func": self.exist_func,
            "not_exist_func": self.not_exist_func,
            "start_with_func": self.start_with_func,
            "not_start_with_func": self.not_start_with_func,
            "start_within_file": self.start_within_file,
            "not_start_within_file": self.not_start_within_file,
            "end_with_func": self.end_with_func,
            "has_user_input": self.has_user_input,
            "start_with_var": self.start_with_var,
        }

        if self.key in key_map:
            check_function = key_map[self.key]
        else:
            return False

        return check_function(self.value, path)


class TraceRuleOld(TraceRuleInterface):
    """
    a rule container, which include a rule and a related checking function
    """

    def __init__(self, key, value, G):
        self.key = key
        self.value = value
        self.graph = G

    def _iter_called_funcs(self, node):
        call_types = {"AST_CALL", "AST_METHOD_CALL", "AST_NEW"}
        names = []
        node_attr = self.graph.get_node_attr(node)
        if node_attr.get("type") in call_types:
            # Special-case method calls so we can match sinks like `res.send` or
            # `fs.readFile` (common in regress tests and docs).
            if node_attr.get("type") == "AST_METHOD_CALL":
                children = self.graph.get_ordered_ast_child_nodes(node)
                if len(children) >= 2:
                    receiver = self.graph.get_name_from_child(children[0], order=1)
                    method = self.graph.get_name_from_child(children[1], order=1)
                    if receiver and method:
                        names.append(f"{receiver}.{method}")
                    if method:
                        names.append(method)
            for child in self.graph.get_all_child_nodes(node):
                name = self.graph.get_name_from_child(child)
                if name:
                    names.append(name)
        # Some graphs store call nodes as children; include those too.
        for child in self.graph.get_all_child_nodes(node):
            child_attr = self.graph.get_node_attr(child)
            if child_attr.get("type") in call_types:
                if child_attr.get("type") == "AST_METHOD_CALL":
                    children = self.graph.get_ordered_ast_child_nodes(child)
                    if len(children) >= 2:
                        receiver = self.graph.get_name_from_child(children[0], order=1)
                        method = self.graph.get_name_from_child(children[1], order=1)
                        if receiver and method:
                            names.append(f"{receiver}.{method}")
                        if method:
                            names.append(method)
                name = self.graph.get_name_from_child(child)
                if name:
                    names.append(name)
        return names

    def exist_func(self, func_names, path):
        """
        check whether in the path, all functions within {func_names} exists

        Args:
            func_names: a list of function names that need to appear in the path
            path: the path need to be checked

        Returns:
            checking result
        """
        called_func_list = set()
        for node in path:
            called_func_list.update(self._iter_called_funcs(node))

        # print("@@@@@@@@ CALLED FUNCTIONS", called_func_list)

        for called_func_name in called_func_list:
            if called_func_name in func_names:
                return True

        return False

    def not_exist_func(self, func_names, path):
        """
        check if there exist a function named func_names in the path
        """
        return not self.exist_func(func_names, path)

    def start_with_func(self, func_names, path):
        """
        check whether a path starts with a function

        Args:
            func_names: the possible function names
            path: the path needed to be checked
        Return:
            True or False
        """
        start_node = path[0]

        for cur_func in self._iter_called_funcs(start_node):
            if cur_func in func_names:
                return True
        return False

    def not_start_with_func(self, func_names, path):
        """
        check whether a path starts with a function

        Args:
            func_names: the possible function names
            path: the path needed to be checked
        Return:
            True or False
        """
        return not self.start_with_func(func_names, path)

    def not_start_within_file(self, file_names, path):
        """
        check whether a path starts within a file
        Args:
            file_names: the possible file names
            path: the path to be checked
        Return:
            True or False
        """
        start_node = path[0]
        return not self.start_within_file(file_names, path)

    def end_with_func(self, func_names, path):
        """
        check whether a path ends with a function

        Args:
            func_names: the possible function names
            path: the path needed to be checked
        Return:
            True or False
        """
        end_node = path[-1]

        for cur_func in self._iter_called_funcs(end_node):
            if cur_func in func_names:
                return True
        return False

    def start_within_file(self, file_names, path):
        """
        check whether a path starts within a file
        Args:
            file_names: the possible file names
            path: the path to be checked
        Return:
            True or False
        """
        start_node = path[0]

        file_path = self.graph.get_node_file_path(start_node)
        if file_path is None:
            return False
        file_base = file_path if "/" not in file_path else file_path.split("/")[-1]
        return file_path in file_names or file_base in file_names

    def start_with_var(self, var_names, path):
        # TODO: not finished, need to update the var name finding algorithm
        """
        check whether a path starts with a variable
        Args:
            var_names: the possible var names
            path: the path to be checked
        Return:
            True or False
        """
        start_node = path[0]

        path_start_var_name = self.graph.get_name_from_child(start_node)
        cur_node = self.graph.get_node_attr(start_node)
        if path_start_var_name is None:
            return False
        return path_start_var_name in var_names

    def has_user_input(self, _, path):
        """
        check if any node in this path contains user input
        user input is defined as in the http, process or
        the arguments of the module entrance functions

        we check by the obj in the edges
        Args:
            path: the path
        Return:
            True or False
        """
        pre_node = None
        for node in path:
            node_name = self.graph.get_name_from_child(node)
            if node_name and node_name.startswith("OPGen_TAINTED_VAR"):
                return True
            if not pre_node:
                pre_node = node
                continue

            cur_edges = self.graph.get_edge_attr(pre_node, node)
            # print("{} --{}--> {}".format(pre_node, cur_edges, node))
            if not cur_edges:
                continue
            for k in cur_edges:
                if (
                    "type:TYPE" in cur_edges[k]
                    and cur_edges[k]["type:TYPE"] == "OBJ_REACHES"
                ):
                    obj = cur_edges[k]["obj"]
                    obj_attr = self.graph.get_node_attr(obj)
                    if "tainted" in obj_attr and obj_attr["tainted"]:
                        return True
            pre_node = node

            """
            all_child = self.graph.get_all_child_nodes(node)
            objs = []
            for child in all_child:
                objs += self.graph.get_in_edges(child, edge_type='OBJ_TO_AST')
            for obj in objs:
                node_attr = self.graph.get_node_attr(obj[0])
                # here we only keep the obj which in the OBJ_REACHES edges
                if 'tainted' in node_attr and node_attr['tainted']:
                    print(obj[0], node_attr, self.graph.get_node_attr(obj[1]))
                    return True
            """
        if self.start_within_file(["http.js", "process.js", "yargs.js"], path):
            return True
        return False

    def check(self, path):
        """
        select the checking function and run it based on the key value
        Return:
            the running result of the obj
        """
        key_map = {
            "exist_func": self.exist_func,
            "not_exist_func": self.not_exist_func,
            "start_with_func": self.start_with_func,
            "not_start_with_func": self.not_start_with_func,
            "start_within_file": self.start_within_file,
            "not_start_within_file": self.not_start_within_file,
            "end_with_func": self.end_with_func,
            "has_user_input": self.has_user_input,
            "start_with_var": self.start_with_var,
        }

        if self.key in key_map:
            check_function = key_map[self.key]
        else:
            return False

        return check_function(self.value, path)


class TraceRule(TraceRuleInterface):
    """
    Trace rule wrapper that delegates to either new or old trace rule implementation.

    This class provides a unified interface for trace rules, automatically
    selecting between TraceRuleNew and TraceRuleOld based on the graph's
    configuration.

    Args:
        key (str): Rule function name (e.g., 'has_user_input', 'end_with_func')
        value: Rule arguments (can be None, a list, or other types)
        G (Graph): The graph object for context

    Example:
        >>> rule = TraceRule('has_user_input', None, G)
        >>> if rule.check(path):
        ...     print("Path contains user input")
    """

    def __init__(self, key, value, G):
        if G.new_trace_rule:
            self.trace_rule = TraceRuleNew(key, value, G)
        else:
            self.trace_rule = TraceRuleOld(key, value, G)

    def check(self, path):
        """
        Check if a path satisfies this trace rule.

        Args:
            path (list): List of node IDs representing an execution path

        Returns:
            bool: True if the path satisfies the rule, False otherwise
        """
        return self.evaluate(path)["passed"]

    def evaluate(self, path):
        """Return structured rule evaluation details for a path."""
        return {
            "name": self.trace_rule.key,
            "arguments": self.trace_rule.value,
            "passed": bool(self.trace_rule.check(path)),
        }
