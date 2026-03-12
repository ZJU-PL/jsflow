from types import SimpleNamespace


class FakeGraph:
    def __init__(
        self,
        new_trace_rule,
        node_attrs=None,
        edge_attrs=None,
        file_paths=None,
        name_map=None,
        parent_edges=None,
        child_nodes=None,
        line_codes=None,
    ):
        self.new_trace_rule = new_trace_rule
        self.node_attrs = node_attrs or {}
        self.edge_attrs = edge_attrs or {}
        self.file_paths = file_paths or {}
        self.name_map = name_map or {}
        self.parent_edges = parent_edges or {}
        self.child_nodes = child_nodes or {}
        self.line_codes = line_codes or {}
        self.vul_type = "xss"
        self.auto_exploit = False
        self.success_detect = False
        self.success_exploit = False
        self.log_dir = "logs/test"
        self.entry_file_path = "/tmp/input.js"
        self.vul_files = set()
        self.covered_stat = set()
        self.covered_func = set()
        self.num_of_cf_paths = 0
        self.num_of_prec_cf_paths = 0
        self.num_of_full_cf_paths = 0
        self.rerun_counter = 0
        self.proto_pollution = set()
        self.ipt_use = set()
        self.ipt_write = set()
        self.check_proto_pollution = False
        self.check_ipt = False
        self.exploit_reports = []
        self.logger = SimpleNamespace(debug=lambda *args, **kwargs: None)

    def get_node_attr(self, node):
        return self.node_attrs.get(node, {})

    def get_in_edges(self, node, edge_type=None):
        return self.parent_edges.get(node, [])

    def get_name_from_child(self, node, order=None):
        return self.name_map.get(node)

    def get_node_file_path(self, node):
        return self.file_paths.get(node)

    def get_edge_attr(self, u, v):
        return self.edge_attrs.get((u, v), {})

    def get_all_child_nodes(self, node):
        return self.child_nodes.get(node, [])

    def get_node_line_code(self, node):
        return self.line_codes.get(node)

    def get_total_num_statements(self):
        return len(self.covered_stat)

    def get_total_num_functions(self):
        return len(self.covered_func)
