"""Conservative config analysis; unsupported Compose environment forms stay unknown."""
import ast
import re
import shlex


def python_debug_lines(source):
    tree = ast.parse(source)
    lines = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if isinstance(value, ast.Constant) and value.value is True:
                if any((isinstance(t, ast.Name) and t.id.lower() == 'debug') or (isinstance(t, ast.Attribute) and t.attr.lower() == 'debug') or
                       (isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant) and str(t.slice.value).lower() == 'debug') for t in targets):
                    lines.add(node.lineno)
        if isinstance(node, ast.keyword) and node.arg == 'debug' and isinstance(node.value, ast.Constant) and node.value.value is True:
            lines.add(node.lineno)
    return lines


def compose_environment(source):
    """Parse block mapping/list environment subset. Return (line,key,value), unknowns.

    Not a general YAML parser: aliases, flow maps, interpolation and complex scalars
    are explicitly returned as unknown rather than certified clean.
    """
    entries, unknown = [], []
    indent = None
    for lineno, line in enumerate(source.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        level = len(line) - len(line.lstrip())
        if re.match(r'''^(?:environment|"environment"|'environment')\s*:''', stripped):
            indent = level
            rest = stripped.split(':', 1)[1].strip()
            if rest and not rest.startswith('#'):
                unknown.append(lineno)
            continue
        if indent is None:
            continue
        if level <= indent:
            indent = None; continue
        try:
            if stripped.startswith('-'):
                parts = shlex.split(stripped[1:].strip(), comments=True)
                if len(parts) != 1 or '=' not in parts[0]:
                    unknown.append(lineno); continue
                key, value = parts[0].split('=', 1)
            else:
                if ':' not in stripped:
                    unknown.append(lineno); continue
                key, raw = stripped.split(':', 1)
                key = key.strip().strip('\"\'')
                parts = shlex.split(raw.strip(), comments=True)
                if len(parts) != 1:
                    unknown.append(lineno); continue
                value = parts[0]
            if any(c in value for c in ('$', '*', '&', '{', '}', '|', '>')) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key):
                unknown.append(lineno); continue
            entries.append((lineno, key, value))
        except ValueError:
            unknown.append(lineno)
    return entries, unknown
