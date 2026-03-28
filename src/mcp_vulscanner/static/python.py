"""AST-backed Python analyzer."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable

from .base import RuleMatch, SourceFile, StaticAnalyzer, executable_sink_evidence, score_features


SUBPROCESS_SINKS = {
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_output",
    "subprocess.check_call",
}
NETWORK_SINKS = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.patch",
    "requests.request",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.patch",
    "httpx.request",
    "urllib.request.urlopen",
    "urllib.request.Request",
    "urllib.urlopen",
}
FILE_SINKS = {
    "open",
    "shutil.copy",
    "shutil.copyfile",
    "shutil.move",
}
FILE_METHOD_SINKS = {"write_text", "write_bytes"}
PATH_BUILDERS = {"Path", "pathlib.Path", "Path.joinpath", "pathlib.Path.joinpath", "urllib.request.Request"}
RISKY_INPUT_NAMES = {"cmd", "command", "url", "path", "download_path", "base_url", "headers", "params", "query"}


class PythonAnalyzer(StaticAnalyzer):
    """Detect executable sinks in Python MCP server code."""

    language = "python"

    def supports(self, path: Path) -> bool:
        """Return whether the file extension is supported."""

        return path.suffix.lower() == ".py"

    def analyze(self, source_file: SourceFile) -> list[RuleMatch]:
        """Analyze Python content with AST-backed sink matching."""

        tree = ast.parse(source_file.content, filename=str(source_file.path))
        tool_handlers = _collect_tool_handlers(tree)
        return _PythonVisitor(source_file, tool_handlers).collect(tree)


class _PythonVisitor(ast.NodeVisitor):
    """Collect executable sink matches from runtime code."""

    def __init__(self, source_file: SourceFile, tool_handlers: dict[str, str]) -> None:
        self._source_file = source_file
        self._tool_handlers = tool_handlers
        self._findings: list[RuleMatch] = []

    def collect(self, tree: ast.AST) -> list[RuleMatch]:
        """Return the collected findings for a module."""

        self.visit(tree)
        return self._findings

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        """Analyze one function body with local taint tracking."""

        tool_name = self._tool_handlers.get(node.name)
        state = _FunctionState(
            tool_name=tool_name,
            tainted_names={"arguments"},
        )
        for argument in node.args.args:
            state.tainted_names.add(argument.arg)
        for statement in node.body:
            self._scan_statement(statement, state)

    def _scan_statement(self, statement: ast.stmt, state: "_FunctionState") -> None:
        """Track taint and collect call-based findings."""

        if isinstance(statement, ast.Assign):
            tainted = _expr_is_tainted(statement.value, state.tainted_names)
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    if tainted:
                        state.tainted_names.add(target.id)
                    else:
                        state.tainted_names.discard(target.id)
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
            if _expr_is_tainted(statement.value, state.tainted_names):
                state.tainted_names.add(statement.target.id)
        elif isinstance(statement, ast.With):
            for item in statement.items:
                self._scan_call(item.context_expr, state)
            for child in statement.body:
                self._scan_statement(child, state)
            return
        elif isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
            self._scan_call(statement.value, state)
        elif isinstance(statement, ast.Return):
            for call in _walk_calls(statement.value):
                self._scan_call(call, state)
            return
        elif isinstance(statement, ast.If):
            for child in statement.body:
                self._scan_statement(child, state)
            for child in statement.orelse:
                self._scan_statement(child, state)
            return
        elif isinstance(statement, (ast.For, ast.While, ast.Try)):
            for child in ast.iter_child_nodes(statement):
                if isinstance(child, ast.stmt):
                    self._scan_statement(child, state)
            return

        for child in ast.iter_child_nodes(statement):
            if isinstance(child, ast.Call):
                self._scan_call(child, state)

    def _scan_call(self, call: ast.Call, state: "_FunctionState") -> None:
        """Inspect one executable call node."""

        full_name = _full_name(call.func)
        tool_name = state.tool_name
        reachable = tool_name is not None
        suppression_reason = None if reachable else "unreachable_tool"
        snippet = ast.get_source_segment(self._source_file.content, call) or ""

        if _is_command_injection(call, full_name, state.tainted_names):
            self._findings.append(
                _build_match(
                    source_file=self._source_file,
                    call=call,
                    rule_id="py.command-injection",
                    vulnerability_class="command-injection",
                    sink="subprocess",
                    message="Potential command execution from executable user-controlled input.",
                    snippet=snippet,
                    tool_name=tool_name,
                    reachable=reachable,
                    suppression_reason=suppression_reason,
                )
            )
            return

        if _is_ssrf(call, full_name, state.tainted_names):
            self._findings.append(
                _build_match(
                    source_file=self._source_file,
                    call=call,
                    rule_id="py.ssrf",
                    vulnerability_class="ssrf",
                    sink="network-request",
                    message="Potential outbound request from executable user-controlled URL or request metadata.",
                    snippet=snippet,
                    tool_name=tool_name,
                    reachable=reachable,
                    suppression_reason=suppression_reason,
                )
            )
            return

        if _is_file_write(call, full_name, state.tainted_names):
            self._findings.append(
                _build_match(
                    source_file=self._source_file,
                    call=call,
                    rule_id="py.file-write",
                    vulnerability_class="arbitrary-file-write",
                    sink="filesystem-write",
                    message="Potential file write or path traversal from executable user-controlled path input.",
                    snippet=snippet,
                    tool_name=tool_name,
                    reachable=reachable,
                    suppression_reason=suppression_reason,
                )
            )


class _FunctionState:
    """Local taint-tracking state for one function."""

    def __init__(self, *, tool_name: str | None, tainted_names: set[str]) -> None:
        self.tool_name = tool_name
        self.tainted_names = set(tainted_names)


def _collect_tool_handlers(tree: ast.AST) -> dict[str, str]:
    """Collect decorator-based MCP tool registrations."""

    handlers: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call) and _full_name(decorator.func) == "tool":
                if decorator.args and isinstance(decorator.args[0], ast.Constant) and isinstance(decorator.args[0].value, str):
                    handlers[node.name] = decorator.args[0].value
    return handlers


def _build_match(
    *,
    source_file: SourceFile,
    call: ast.Call,
    rule_id: str,
    vulnerability_class: str,
    sink: str,
    message: str,
    snippet: str,
    tool_name: str | None,
    reachable: bool,
    suppression_reason: str | None,
) -> RuleMatch:
    """Create a structured match for one executable sink."""

    evidence = [
        executable_sink_evidence(sink),
        *score_features(
            source_file.content,
            snippet,
            tool_name=tool_name,
            reachable=reachable,
        ),
    ]
    return RuleMatch(
        rule_id=rule_id,
        vulnerability_class=vulnerability_class,
        line=call.lineno,
        tool_name=tool_name,
        sink=sink,
        symbol=None,
        snippet=" ".join(snippet.split()),
        evidence=evidence,
        message=message,
        reachable=reachable,
        suppression_reason=suppression_reason,
    )


def _is_command_injection(call: ast.Call, full_name: str, tainted_names: set[str]) -> bool:
    """Return whether a call is a command sink with user-controlled input."""

    if full_name not in SUBPROCESS_SINKS:
        return False
    shell_true = any(
        keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
        for keyword in call.keywords
    )
    first_arg = call.args[0] if call.args else None
    return shell_true or _expr_is_tainted(first_arg, tainted_names)


def _is_ssrf(call: ast.Call, full_name: str, tainted_names: set[str]) -> bool:
    """Return whether a call is a network sink with user-controlled request data."""

    if full_name not in NETWORK_SINKS:
        return False
    values = list(call.args) + [keyword.value for keyword in call.keywords]
    return any(_expr_is_tainted(value, tainted_names) for value in values)


def _is_file_write(call: ast.Call, full_name: str, tainted_names: set[str]) -> bool:
    """Return whether a call is a file-system sink with user-controlled paths."""

    if full_name in FILE_SINKS:
        if full_name == "open":
            mode = call.args[1] if len(call.args) > 1 else next((keyword.value for keyword in call.keywords if keyword.arg == "mode"), None)
            if not _is_write_mode(mode):
                return False
        first_arg = call.args[0] if call.args else None
        return _expr_is_tainted(first_arg, tainted_names)

    if isinstance(call.func, ast.Attribute) and call.func.attr in FILE_METHOD_SINKS:
        return _expr_is_tainted(call.func.value, tainted_names)
    if isinstance(call.func, ast.Attribute) and call.func.attr == "open":
        mode = call.args[0] if call.args else next((keyword.value for keyword in call.keywords if keyword.arg == "mode"), None)
        return _is_write_mode(mode) and _expr_is_tainted(call.func.value, tainted_names)
    return False


def _expr_is_tainted(expr: ast.AST | None, tainted_names: set[str]) -> bool:
    """Return whether an expression depends on user-controlled input."""

    if expr is None:
        return False
    if isinstance(expr, ast.Name):
        return expr.id in tainted_names or expr.id in RISKY_INPUT_NAMES
    if isinstance(expr, ast.Constant):
        return False
    if isinstance(expr, ast.JoinedStr):
        return any(_expr_is_tainted(value, tainted_names) for value in expr.values)
    if isinstance(expr, ast.FormattedValue):
        return _expr_is_tainted(expr.value, tainted_names)
    if isinstance(expr, ast.Subscript):
        if isinstance(expr.value, ast.Name) and expr.value.id == "arguments":
            return True
        return _expr_is_tainted(expr.value, tainted_names) or _expr_is_tainted(expr.slice, tainted_names)
    if isinstance(expr, ast.Call):
        full_name = _full_name(expr.func)
        if full_name in PATH_BUILDERS:
            return any(_expr_is_tainted(arg, tainted_names) for arg in expr.args) or any(
                _expr_is_tainted(keyword.value, tainted_names) for keyword in expr.keywords
            )
        if isinstance(expr.func, ast.Attribute) and expr.func.attr == "get":
            return _expr_is_tainted(expr.func.value, tainted_names)
        return any(_expr_is_tainted(arg, tainted_names) for arg in expr.args) or any(
            _expr_is_tainted(keyword.value, tainted_names) for keyword in expr.keywords
        )
    if isinstance(expr, ast.Attribute):
        return _expr_is_tainted(expr.value, tainted_names)
    if isinstance(expr, ast.BinOp):
        return _expr_is_tainted(expr.left, tainted_names) or _expr_is_tainted(expr.right, tainted_names)
    if isinstance(expr, ast.Dict):
        return any(_expr_is_tainted(key, tainted_names) for key in expr.keys if key is not None) or any(
            _expr_is_tainted(value, tainted_names) for value in expr.values
        )
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return any(_expr_is_tainted(value, tainted_names) for value in expr.elts)
    return any(_expr_is_tainted(child, tainted_names) for child in ast.iter_child_nodes(expr))


def _is_write_mode(mode_expr: ast.AST | None) -> bool:
    """Return whether a mode expression is a write-like mode."""

    if isinstance(mode_expr, ast.Constant) and isinstance(mode_expr.value, str):
        return any(flag in mode_expr.value for flag in ("w", "a"))
    return False


def _walk_calls(expr: ast.AST | None) -> Iterable[ast.Call]:
    """Yield nested calls from an expression."""

    if expr is None:
        return []
    return [node for node in ast.walk(expr) if isinstance(node, ast.Call)]


def _full_name(node: ast.AST) -> str:
    """Return a dotted name for a simple call target."""

    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _full_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""
