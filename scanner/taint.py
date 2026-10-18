"""Derin scanner motoru: taint tracking + veri akis analizi."""
import ast


def full_attr(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


TAINT_SOURCES = {
    "input", "sys.argv",
    "request.args.get", "request.form.get", "request.args",
    "request.form", "request.data", "request.json",
    "os.environ.get", "os.getenv", "sys.stdin.read",
}
TAINT_PASSTHROUGH = {"format", "strip", "encode", "decode", "lower", "upper", "replace", "join", "split", "%"}


class TaintTracker(ast.NodeVisitor):
    """Kullanici girdisinin tehlikeli fonksiyonlara ulasip ulasmadigini izler."""

    def __init__(self):
        self.tainted = set()  # tainted degisken isimleri
        self.flows = []  # (lineno, source, sink) listesi
        self.stack = []

    def visit_FunctionDef(self, node):
        old = set(self.tainted)
        # parametreleri supheli sayma, ama request/input atamalarini yakala
        self.generic_visit(node)
        self.tainted = old

    visit_AsyncFunctionDef = visit_FunctionDef

    def _expr_tainted(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.tainted
        if isinstance(node, ast.Call):
            fname = full_attr(node.func) if isinstance(node.func, (ast.Attribute, ast.Name)) else ""
            if fname in TAINT_SOURCES or fname == "input":
                return True
            if isinstance(node.func, ast.Name) and node.func.id == "input":
                return True
            return any(self._expr_tainted(a) for a in node.args)
        if isinstance(node, ast.JoinedStr):
            return any(self._expr_tainted(v.value) if isinstance(v, ast.FormattedValue) else False for v in node.values)
        if isinstance(node, ast.BinOp):
            return self._expr_tainted(node.left) or self._expr_tainted(node.right)
        if isinstance(node, ast.Attribute):
            full = full_attr(node)
            if full in TAINT_SOURCES:
                return True
            return self._expr_tainted(node.value)
        if isinstance(node, ast.Subscript):
            return self._expr_tainted(node.value)
        return False

    def visit_Assign(self, node):
        try:
            if self._expr_tainted(node.value):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        self.tainted.add(t.id)
                    elif isinstance(t, (ast.Tuple, ast.List)):
                        for e in t.elts:
                            if isinstance(e, ast.Name):
                                self.tainted.add(e.id)
        finally:
            self.generic_visit(node)

    def visit_Call(self, node):
        fname = full_attr(node.func) if isinstance(node.func, (ast.Attribute, ast.Name)) else ""
        sinks = {"eval", "exec", "os.system", "os.popen", "subprocess.call",
                 "subprocess.run", "subprocess.Popen", "execute", "executemany"}
        short = fname.split(".")[-1]
        if fname in sinks or short in ("execute", "executemany", "system"):
            for a in node.args:
                if self._expr_tainted(a):
                    self.flows.append({"line": getattr(node, "lineno", 1), "sink": fname, "tainted": True})
                    break
        self.generic_visit(node)


def taint_flows(tree):
    t = TaintTracker()
    t.visit(tree)
    return t.flows
