"""Offline Next.js GHSA-673q-mjm6-r5xr assessment. Never imports target code."""

import argparse
import collections
import json
import math
import os
from pathlib import Path
import re
import stat
import sys

TOOL_NAME = "next-cache-rce-check"
TOOL_VERSION = "0.1.0"
RULE_ID = "GHSA-673q-mjm6-r5xr"
RULE_DATE = "2026-10-23"
SNAPSHOT_ID = "next-cache-2026-10-23.1"
ADVISORY_URL = "https://github.com/vercel/next.js/security/advisories/GHSA-673q-mjm6-r5xr"
RULE_SOURCES = [ADVISORY_URL, "https://github.com/vercel/next.js/releases/tag/v16.4.1"]
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 40
MAX_JSON_NODES = 200000
MAX_SOURCE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_FILES = 500
MAX_ENTRIES = 10000
MAX_DEPTH = 20
MAX_TOKENS = 100000
MAX_OBSERVATIONS = 256
SOURCE_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts"}
SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "coverage", ".turbo", ".cache"}
CONFIG_FILES = {"next.config.js", "next.config.mjs", "next.config.cjs", "next.config.ts", "next.config.mts"}
UNSUPPORTED_LOCKS = ("yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb")
TYPED_ARRAYS = {"Int8Array", "Uint8Array", "Uint8ClampedArray", "Int16Array", "Uint16Array", "Int32Array", "Uint32Array", "Float16Array", "Float32Array", "Float64Array", "BigInt64Array", "BigUint64Array"}
STATIC_LIMITATION = "Static syntax is candidate evidence, not deployed configuration, data flow, reachability, or exploitability."
RECOMMENDATION = "Upgrade Next.js to 16.4.1 or a later supported patched release; verify the deployed dependency and rebuild/redeploy. Review cached typed-array return paths."
Token = collections.namedtuple("Token", "kind value line start end")


class ScanInputError(ValueError):
    """Controlled input failure; messages never include absolute paths or contents."""


class ScanInterrupted(KeyboardInterrupt):
    """A project scan interruption retaining only completed evidence."""

    def __init__(self, progress):
        super().__init__()
        self.progress = progress


def exact_version(value):
    if not isinstance(value, str) or len(value) > 32:
        return None
    match = re.fullmatch(r"(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})", value)
    return tuple(int(part) for part in match.groups()) if match else None


def classify_version(value, *, conflict=False):
    parsed = exact_version(value)
    if conflict:
        return "unknown", "unknown", "Conflicting observations for this dependency instance."
    if parsed is None:
        return "unknown", "unknown", "Version is missing, malformed, a range, prerelease, or vendor-qualified."
    if parsed[0] != 16 or parsed[1] > 4:
        return "unknown", "unknown", "This snapshot only classifies the verified Next.js 16.0–16.4 release lines."
    if parsed <= (16, 4, 0):
        return "potentially_affected", "affected", "Reported version is in the advisory's affected range; application preconditions need review."
    return "fixed_version_reported", "fixed_reported", "Reported version meets the Next.js 16 fix threshold; installed patch state is not independently attested."


def safe_relative(value):
    if not isinstance(value, str) or not value or len(value) > 240 or "\\" in value:
        return False
    parts = value.split("/")
    return all(p not in {"", ".", ".."} for p in parts) and not re.search(r"[\x00-\x1f\x7f:]", value) and not value.startswith("/")


def bounded_text(root, relative, limit):
    """Read a regular, non-symlink input without following known path links."""
    if not safe_relative(relative):
        raise ScanInputError("Unsafe relative input path was excluded.")
    current = root
    try:
        for part in relative.split("/"):
            current = current / part
            if current.is_symlink():
                raise ScanInputError("Symlink input was excluded.")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(current, flags)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ScanInputError("Non-regular input was excluded.")
            if info.st_size > limit:
                raise ScanInputError("Input exceeds its byte limit.")
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ScanInputError("Input exceeds its byte limit.")
        return data.decode("utf-8-sig")
    except (OSError, UnicodeError) as exc:
        raise ScanInputError("Input could not be read as bounded UTF-8 text.") from exc


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ScanInputError("Duplicate JSON keys are not accepted.")
            result[key] = value
        return result

    def invalid_number(_):
        raise ScanInputError("Non-finite JSON numbers are not accepted.")

    def finite_number(value):
        number = float(value)
        if not math.isfinite(number):
            invalid_number(value)
        return number

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=invalid_number, parse_float=finite_number)
    except (ValueError, RecursionError) as exc:
        raise ScanInputError("Input is not supported strict JSON.") from exc
    if not isinstance(value, dict):
        raise ScanInputError("Input JSON must be an object.")
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > MAX_JSON_DEPTH or nodes > MAX_JSON_NODES:
            raise ScanInputError("Input JSON structure exceeds its depth or node limit.")
        children = item.values() if isinstance(item, dict) else item if isinstance(item, list) else ()
        if nodes + len(pending) + len(children) > MAX_JSON_NODES:
            raise ScanInputError("Input JSON structure exceeds its depth or node limit.")
        pending.extend((child, depth + 1) for child in children)
    return value


def lock_observations(data, path):
    """Extract resolved Next package instances from npm lockfile versions 1–3."""
    version = data.get("lockfileVersion")
    if type(version) is not int or version not in {1, 2, 3}:
        raise ScanInputError("Unsupported npm lockfile version; expected 1, 2, or 3.")
    observations = []
    visited = 0

    def add(location, entry):
        if len(observations) >= MAX_OBSERVATIONS:
            raise ScanInputError("Dependency observation limit reached.")
        if not safe_relative(location) or not isinstance(entry, dict):
            raise ScanInputError("Malformed dependency instance in lockfile.")
        if "name" in entry and entry["name"] != "next":
            raise ScanInputError("Lockfile Next.js package identity is contradictory.")
        if "link" in entry and type(entry["link"]) is not bool:
            raise ScanInputError("Lockfile link flags must be booleans.")
        raw = entry.get("version") if not entry.get("link") else None
        if isinstance(raw, str) and raw.startswith("npm:next@"):
            raw = raw[len("npm:next@"):]
        observations.append({"location": location, "version": raw if isinstance(raw, str) else None, "path": path, "kind": "lockfile"})

    def next_alias(entry):
        raw = entry.get("version") if isinstance(entry, dict) else None
        return isinstance(raw, str) and (raw == "npm:next" or raw.startswith("npm:next@"))

    packages = data.get("packages")
    if version in {2, 3}:
        if not isinstance(packages, dict):
            raise ScanInputError("npm lockfile packages must be an object.")
        if len(packages) > MAX_ENTRIES:
            raise ScanInputError("Lockfile package count exceeds the limit.")
        for location, entry in sorted(packages.items()):
            if location == "node_modules/next" or location.endswith("/node_modules/next") or (isinstance(entry, dict) and entry.get("name") == "next" and location) or next_alias(entry):
                add(location, entry)

    def walk(dependencies, prefix="", depth=0):
        nonlocal visited
        if depth > MAX_DEPTH or not isinstance(dependencies, dict):
            raise ScanInputError("Malformed or excessively nested npm dependencies.")
        for name, entry in sorted(dependencies.items()):
            visited += 1
            if visited > MAX_ENTRIES or not isinstance(entry, dict):
                raise ScanInputError("Malformed or excessive dependency inventory.")
            location = prefix + "node_modules/" + name
            if not safe_relative(location):
                raise ScanInputError("Unsafe dependency path in lockfile.")
            if name == "next" or entry.get("name") == "next" or next_alias(entry):
                add(location, entry)
            if "dependencies" in entry:
                walk(entry["dependencies"], location + "/", depth + 1)

    if version == 1 or (version == 2 and "dependencies" in data):
        walk(data.get("dependencies", {}))
    return observations


def lex_source(source):
    """Small lexer, not a JavaScript parser. Strings/templates/regex stay opaque."""
    tokens = []
    i = 0
    line = 1
    n = len(source)
    while i < n:
        if len(tokens) >= MAX_TOKENS:
            raise ScanInputError("Source token limit reached.")
        start, at_line = i, line
        char = source[i]
        if char.isspace():
            line += char == "\n"
            i += 1
            continue
        if source.startswith("//", i):
            end = source.find("\n", i + 2)
            i = n if end < 0 else end
            continue
        if source.startswith("/*", i):
            end = source.find("*/", i + 2)
            if end < 0:
                raise ScanInputError("Unterminated source comment.")
            line += source.count("\n", i, end + 2)
            i = end + 2
            continue
        if char in "\"'" or char == chr(96):
            quote = char
            i += 1
            value = []
            escaped = False
            while i < n:
                if quote == chr(96) and source.startswith("$" + "{", i):
                    raise ScanInputError("Template interpolation needs AST review; this source file was not analyzed.")
                if source[i] == "\\":
                    escaped = True
                    if i + 1 >= n:
                        raise ScanInputError("Unterminated source string.")
                    line += source[i + 1] == "\n"
                    i += 2
                elif source[i] == quote:
                    i += 1
                    break
                else:
                    if source[i] == "\n" and quote != chr(96):
                        raise ScanInputError("Unterminated source string.")
                    line += source[i] == "\n"
                    value.append(source[i])
                    i += 1
            else:
                raise ScanInputError("Unterminated source string.")
            kind = "template" if quote == chr(96) else "string"
            tokens.append(Token(kind, "" if escaped else "".join(value), at_line, start, i))
            continue
        regex_start = not tokens or tokens[-1].value in {"=", "(", "[", ",", ":", ";", "return", "throw", "yield", "await", "case", "delete", "typeof", "void", "else", "do", "=>", "!", "{", "?", "+", "-", "*", "%", "&", "|", "^", "&&", "||", "==", "!=", ">", "~"}
        if char == "/" and not regex_start:
            # A slash after a closing block/parenthesis or in JSX can be a
            # statement-level regex; never lex its body as ordinary source.
            previous = tokens[-1]
            if previous.kind not in {"identifier", "number", "string", "template", "regex"} and previous.value != "]":
                raise ScanInputError("Ambiguous slash or JSX syntax needs AST review; this source file was not analyzed.")
        if char == "/" and regex_start:
            i += 1
            in_class = False
            while i < n:
                if source[i] == "\\":
                    i += 2
                elif source[i] == "\n":
                    raise ScanInputError("Unterminated source regex.")
                elif source[i] == "[":
                    in_class = True
                    i += 1
                elif source[i] == "]":
                    in_class = False
                    i += 1
                elif source[i] == "/" and not in_class:
                    i += 1
                    while i < n and source[i].isalpha():
                        i += 1
                    break
                else:
                    i += 1
            else:
                raise ScanInputError("Unterminated source regex.")
            tokens.append(Token("regex", "", at_line, start, i))
            continue
        if char.isalpha() or char in "_$":
            i += 1
            while i < n and (source[i].isalnum() or source[i] in "_$"):
                i += 1
            tokens.append(Token("identifier", source[start:i], at_line, start, i))
            continue
        if char.isdigit():
            i += 1
            while i < n and (source[i].isalnum() or source[i] in "._"):
                i += 1
            tokens.append(Token("number", source[start:i], at_line, start, i))
            continue
        punct = next((p for p in ("...", "=>", "?.", "==", "!=", "&&", "||") if source.startswith(p, i)), char)
        i += len(punct)
        tokens.append(Token("punct", punct, at_line, start, i))
    return tokens


def bracket_pairs(tokens):
    stack, pairs = [], {}
    closes = {")": "(", "]": "[", "}": "{"}
    for i, token in enumerate(tokens):
        if token.kind != "punct":
            continue
        if token.value in {"(", "[", "{"}:
            stack.append(i)
            if len(stack) > 256:
                raise ScanInputError("Source nesting limit reached.")
        elif token.value in closes:
            if not stack or tokens[stack[-1]].value != closes[token.value]:
                raise ScanInputError("Unbalanced source delimiters.")
            opening = stack.pop()
            pairs[opening] = i
            pairs[i] = opening
    if stack:
        raise ScanInputError("Unbalanced source delimiters.")
    return pairs


def directive_at(tokens, start, end):
    i = start
    while i < end and tokens[i].kind == "string":
        token = tokens[i]
        after = i + 1
        terminates = after == end or tokens[after].value == ";" or (tokens[after].line > token.line and tokens[after].value in {"export", "import", "async", "function", "const", "let", "var", "return", "if"})
        if not terminates:
            return None
        if token.value == "use cache":
            return token
        i = after + (after < end and tokens[after].value == ";")
    return None


def function_regions(tokens, pairs):
    regions = []
    controls = {"if", "while", "for", "switch", "catch", "with"}
    for i, token in enumerate(tokens):
        if token.value != "{" or token.kind != "punct" or i == 0:
            continue
        previous_index = i - 1
        # Support simple TypeScript return annotations without evaluating types.
        if tokens[previous_index].value not in {")", "=>"}:
            candidate = previous_index
            allowed = {"identifier", "number"}
            while candidate >= max(0, i - 128) and (
                tokens[candidate].kind in allowed or tokens[candidate].value in {"[", "]", "<", ">", ".", ",", "?", "|", "&"}
            ):
                candidate -= 1
            if candidate > 0 and tokens[candidate].value == ":" and tokens[candidate - 1].value == ")":
                previous_index = candidate - 1
        prev = tokens[previous_index].value
        start = None
        if prev == "=>":
            start = i - 1
            if i >= 2 and tokens[i - 2].value == ")":
                start = pairs[i - 2]
            elif i >= 2:
                start = i - 2
        elif prev == ")":
            opening = pairs[previous_index]
            before = tokens[opening - 1].value if opening else ""
            if before not in controls and (before == "function" or (opening > 1 and tokens[opening - 2].value in {"function", "*"}) or (opening and tokens[opening - 1].kind == "identifier" and before not in {"return", "new"})):
                start = max(0, opening - 2)
        if start is not None:
            prefix_start = start
            while prefix_start > 0 and tokens[prefix_start - 1].value not in {";", "}", "{"}:
                prefix_start -= 1
            exported = any(t.value == "export" for t in tokens[prefix_start:start + 1])
            regions.append((start, i, pairs[i], exported))
            if len(regions) > 1000:
                raise ScanInputError("Source function count limit reached.")
    return regions


def array_constructors(tokens):
    count = 0
    for i, token in enumerate(tokens[:-2]):
        if token.kind == "identifier" and token.value == "new" and tokens[i + 1].value in TYPED_ARRAYS and tokens[i + 2].value == "(":
            count += 1
    return count


def source_candidates(source, path):
    tokens = lex_source(source)
    pairs = bracket_pairs(tokens)
    candidates = []
    if path.split("/")[-1] in CONFIG_FILES:
        for i in range(len(tokens) - 2):
            token = tokens[i]
            if token.value == "cacheComponents" and token.kind in {"identifier", "string"} and tokens[i + 1].value == ":":
                value = tokens[i + 2].value
                label = "enabled" if value == "true" else "disabled" if value == "false" else "dynamic"
                candidates.append({"condition": "cache-components", "path": path, "line": token.line, "detail": "Static cacheComponents setting: " + label + "; effective deployed configuration is unknown."})
    file_directive = directive_at(tokens, 0, len(tokens))
    regions = function_regions(tokens, pairs)
    for start, opening, closing, exported in regions:
        cache_directive = directive_at(tokens, opening + 1, closing)
        if cache_directive is None and not (file_directive is not None and exported):
            continue
        chosen = cache_directive or file_directive
        candidates.append({"condition": "use-cache", "path": path, "line": chosen.line, "detail": "A function has a use-cache directive or is explicitly exported from a use-cache module."})
        nested = {r[0]: r[2] for r in regions if opening < r[0] < closing and r[2] < closing}
        direct = []
        i = opening + 1
        while i < closing:
            if i in nested:
                i = nested[i] + 1
            else:
                direct.append(tokens[i])
                i += 1
        # Count constructors only within one return expression in this function.
        for j, token in enumerate(direct):
            if token.kind != "identifier" or token.value != "return":
                continue
            if j + 1 == len(direct) or direct[j + 1].line > token.line:
                continue
            expression = []
            depth = 0
            for k in range(j + 1, len(direct)):
                part = direct[k]
                if depth == 0 and part.value in {";", "}", "return"}:
                    break
                if depth == 0 and part.value in {"const", "let", "var", "function", "class", "export", "import", "throw", "break", "continue", "debugger", "if", "for", "while"}:
                    break
                continuation = {"(", "[", ".", "?.", "?", ":", ",", "+", "-", "*", "/", "%", "&", "|", "^", "&&", "||", "==", "!=", "<", ">", "="}
                if depth == 0 and expression and part.line > expression[-1].line and part.value not in continuation and expression[-1].value not in continuation | {"await", "new", "yield", "typeof", "void", "delete", "in", "instanceof"}:
                    break
                if part.kind == "punct" and part.value in {"(", "[", "{"}:
                    depth += 1
                elif part.kind == "punct" and part.value in {")", "]", "}"}:
                    depth -= 1
                    if depth < 0:
                        break
                expression.append(part)
            # A concise arrow in a returned expression introduces another
            # function scope that this lexer cannot safely delimit.
            if not any(part.value == "=>" and part.kind == "punct" for part in expression) and array_constructors(expression) >= 2:
                candidates.append({"condition": "multiple-typed-array-return", "path": path, "line": token.line, "detail": "Candidate return expression contains multiple typed-array constructions in the same cached function; value flow and execution are unverified."})
    unique = {(c["condition"], c["path"], c["line"], c["detail"]): c for c in candidates}
    return [unique[key] for key in sorted(unique)]


def inventory_project(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ScanInputError("Project root must be a real directory, not a symlink.")
    root = root.absolute()
    observations, candidates, limitations, protected = [], [], [], []
    total_bytes = 0
    complete = True
    inventory_complete = True

    def issue(message, *, inventory=False):
        nonlocal complete, inventory_complete
        complete = False
        if inventory:
            inventory_complete = False
        if message not in limitations:
            limitations.append(message)

    def read(relative, limit):
        nonlocal total_bytes
        protected.append(root / relative)
        text = bounded_text(root, relative, limit)
        total_bytes += len(text.encode("utf-8"))
        if total_bytes > MAX_TOTAL_BYTES:
            raise ScanInputError("Total input byte limit reached.")
        return text

    inventory_finished = False
    try:
        for name in ("package-lock.json", "npm-shrinkwrap.json"):
            if os.path.lexists(root / name):
                try:
                    observations.extend(lock_observations(strict_json(read(name, MAX_JSON_BYTES)), name))
                except ScanInputError as exc:
                    issue(name + ": " + str(exc), inventory=True)
        for name in UNSUPPORTED_LOCKS:
            if os.path.lexists(root / name):
                protected.append(root / name)
                issue(name + ": this lockfile format is explicitly unsupported; provide a verified npm lockfile or --next-version.", inventory=True)
        manifest = "package.json"
        if os.path.lexists(root / manifest):
            try:
                data = strict_json(read(manifest, MAX_JSON_BYTES))
                declarations = []
                for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                    value = data.get(section, {})
                    if not isinstance(value, dict):
                        raise ScanInputError("Malformed package declaration map.")
                    if "next" in value:
                        declarations.append(value["next"])
                if declarations:
                    candidates.append({"condition": "dependency-declaration", "path": manifest, "line": 1, "detail": "Next.js is declared in package.json; declarations (including exact pins) do not prove an installed/resolved version."})
            except ScanInputError as exc:
                issue(manifest + ": " + str(exc), inventory=True)
        installed = "node_modules/next/package.json"
        if os.path.lexists(root / installed):
            try:
                data = strict_json(read(installed, MAX_JSON_BYTES))
                if data.get("name") != "next":
                    raise ScanInputError("Installed package identity does not match next.")
                observations.append({"location": "node_modules/next", "version": data.get("version") if isinstance(data.get("version"), str) else None, "path": installed, "kind": "installed_metadata"})
            except ScanInputError as exc:
                issue(installed + ": " + str(exc), inventory=True)

        inventory_finished = True
        stack = [(root, 0)]
        entries_seen = 0
        source_count = 0
        while stack:
            directory, depth = stack.pop()
            try:
                with os.scandir(directory) as entries:
                    batch = []
                    for entry in entries:
                        entries_seen += 1
                        if entries_seen > MAX_ENTRIES:
                            issue("Directory entry limit reached; source scan incomplete.")
                            break
                        batch.append(entry)
                    if entries_seen > MAX_ENTRIES:
                        break
                for entry in sorted(batch, key=lambda e: e.name, reverse=True):
                    relative = (directory / entry.name).relative_to(root).as_posix()
                    if not safe_relative(relative):
                        issue("Unsafe or excessive relative source path excluded.")
                        continue
                    if entry.name in SKIP_DIRS:
                        continue
                    if entry.is_symlink():
                        issue("Symlink source entry excluded; source scan incomplete.")
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        if depth >= MAX_DEPTH:
                            issue("Directory depth limit reached; source scan incomplete.")
                        else:
                            stack.append((Path(entry.path), depth + 1))
                        continue
                    if Path(entry.name).suffix not in SOURCE_SUFFIXES:
                        continue
                    source_count += 1
                    if source_count > MAX_FILES:
                        issue("Source file limit reached; source scan incomplete.")
                        stack.clear()
                        break
                    if not entry.is_file(follow_symlinks=False):
                        issue("Non-regular source entry excluded.")
                        continue
                    try:
                        source = read(relative, MAX_SOURCE_BYTES)
                        if re.fullmatch(r"(?:src/)?app/(?:.+/)?(?:page|layout|route)\.(?:js|jsx|ts|tsx|mjs|cjs)", relative):
                            candidates.append({"condition": "app-router", "path": relative, "line": 1, "detail": "Conventional App Router source file exists; active deployment and route reachability are unknown."})
                        candidates.extend(source_candidates(source, relative))
                    except ScanInputError as exc:
                        issue(relative + ": " + str(exc))
                    if total_bytes > MAX_TOTAL_BYTES:
                        stack.clear()
                        break
                    if len(candidates) > 700:
                        candidates = sorted(candidates, key=lambda c: (c["path"], c["line"], c["condition"]))[:700]
                        issue("Source candidate limit reached.")
                        stack.clear()
                        break
            except OSError:
                issue("A source directory could not be read.")
    except KeyboardInterrupt:
        issue("Interrupted; only completed observations are included.", inventory=not inventory_finished)
        raise ScanInterrupted((observations[:MAX_OBSERVATIONS], candidates[:700], False, sorted(limitations), protected, inventory_complete)) from None
    if len(observations) > MAX_OBSERVATIONS:
        observations = observations[:MAX_OBSERVATIONS]
        issue("Dependency observation limit reached.", inventory=True)
    if len(candidates) > 700:
        candidates = candidates[:700]
        issue("Source candidate limit reached.")
    return observations, candidates, complete, sorted(limitations), protected, inventory_complete


def assessment(observations, candidates, asset_id="project", *, complete=True, inventory_complete=True, limitations=None):
    grouped = collections.defaultdict(list)
    for observation in observations:
        grouped[observation["location"]].append(observation)
    if not grouped:
        grouped["node_modules/next"] = []
    results = []
    for location, observed in sorted(grouped.items()):
        raw_versions = {o["version"] for o in observed}
        conflict = len(raw_versions) > 1
        raw = next(iter(raw_versions)) if len(raw_versions) == 1 else None
        version = raw if exact_version(raw) else None
        status, version_state, reason = classify_version(raw, conflict=conflict)
        evidence = []
        for i, observation in enumerate(sorted(observed, key=lambda o: (o["path"], str(o["version"]), o["kind"])), 1):
            entry = {"id": "version-" + str(i), "kind": "version", "state": "conflicting" if conflict else "present" if exact_version(observation["version"]) else "unknown", "detail": "Next.js version evidence from " + observation["kind"] + "; patch provenance is not attested."}
            if observation["path"]:
                entry["path"] = observation["path"]
            if exact_version(observation["version"]):
                entry["observed_version"] = observation["version"]
            evidence.append(entry)
        predicates = {key: [] for key in ("app-router", "cache-components", "use-cache", "multiple-typed-array-return")}
        relevant_candidates = candidates if location == "node_modules/next" else []
        for i, candidate in enumerate(sorted(relevant_candidates, key=lambda c: (c["path"], c["line"], c["condition"], c["detail"])), 1):
            eid = "source-" + str(i)
            evidence.append({"id": eid, "kind": "configuration" if candidate["condition"] == "cache-components" else "source", "state": "candidate", "detail": candidate["detail"], "path": candidate["path"], "line": candidate["line"]})
            if candidate["condition"] in predicates:
                if len(predicates[candidate["condition"]]) < 100:
                    predicates[candidate["condition"]].append(eid)
        preconditions = [{"id": key, "state": "unknown", "evidence_ids": ids} for key, ids in predicates.items()]
        if not inventory_complete and status == "fixed_version_reported":
            status, version_state = "unknown", "unknown"
            reason = "Incomplete inventory could conceal conflicting or affected dependency evidence."
        evidence.append({"id": "dependency-instance", "kind": "inventory", "state": "present" if observed else "unknown", "detail": "Dependency instance: " + location})
        identity = asset_id + ":next-" + hashlib.sha256(location.encode("utf-8")).hexdigest()[:12]
        results.append(make_result(identity, "next", RULE_ID, status, version=version, build_source="unknown", version_assessment=version_state, confidence="low" if status != "unknown" else "unknown", evidence=evidence, preconditions=preconditions, reasons=[reason, STATIC_LIMITATION], recommendation=RECOMMENDATION, sources=RULE_SOURCES))
    return make_report(TOOL_NAME, TOOL_VERSION, SNAPSHOT_ID, RULE_DATE, results, complete=complete, snapshot_digest=snapshot_digest(RULE_SNAPSHOT), limitations=[STATIC_LIMITATION, "Only npm lockfile versions 1–3 and direct installed next/package.json metadata are supported. Source analysis is lexical; aliases, imports, concise arrows, JSX semantics, templates, and data flow are not resolved."] + list(limitations or []))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline Next.js use-cache typed-array RCE exposure triage (GHSA-673q-mjm6-r5xr). Does not execute project code or contact networks.")
    parser.add_argument("project", nargs="?", help="Project directory to inspect; no default directory is scanned implicitly.")
    parser.add_argument("--next-version", action="append", default=[], metavar="VERSION", help="Explicit reported Next.js version; repeat to preserve conflicting observations.")
    parser.add_argument("--asset-id", default="project", help="Non-sensitive report label (letters, numbers, dots, colons, hyphens, underscores).")
    parser.add_argument("--format", choices=("json", "csv", "html"), default="json")
    parser.add_argument("--output", type=Path, help="Output file outside the assessed project directory; stdout if omitted.")
    parser.add_argument("--force", action="store_true", help="Replace an existing report, never a scanned input.")
    parser.add_argument("--brand", default="CompleteTech LLC", help="HTML report display name.")
    parser.add_argument("--logo", type=Path, help="Local bounded PNG, JPEG, GIF, or WebP logo for HTML reports.")
    parser.add_argument("--fail-on-finding", action="store_true", help="Exit 1 on potentially affected findings.")
    parser.add_argument("--fail-on-unknown", action="store_true", help="Exit 1 when any result is unknown; operational/incomplete errors remain 2.")
    parser.add_argument("--version", action="version", version=TOOL_VERSION)
    args = parser.parse_args(argv)
    if not args.project and not args.next_version:
        parser.error("provide a project directory or --next-version")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}", args.asset_id):
        parser.error("--asset-id must be a non-sensitive label of at most 80 allowed characters")
    if len(args.next_version) > MAX_OBSERVATIONS:
        parser.error("too many reported versions")
    observations, candidates, complete, limitations, protected = [], [], True, [], [Path(__file__)]
    inventory_complete = True
    interrupted = False
    try:
        if args.project:
            if args.output:
                project_root = Path(os.path.abspath(args.project))
                output_path = Path(os.path.abspath(args.output))
                if output_path.is_relative_to(project_root) or output_path.resolve().is_relative_to(project_root.resolve()):
                    raise ScanInputError("Report output must be outside the assessed project directory.")
            try:
                progress = inventory_project(args.project)
            except ScanInterrupted as exc:
                progress = exc.progress
                interrupted = True
            observations, candidates, complete, limitations, inputs, inventory_complete = progress
            protected.extend(inputs)
        observations.extend({"location": "node_modules/next", "version": value, "path": "", "kind": "reported_version"} for value in args.next_version)
        if len(observations) > MAX_OBSERVATIONS:
            observations = observations[:MAX_OBSERVATIONS]
            complete = inventory_complete = False
            limitations.append("Combined dependency observation limit reached.")
        report = assessment(observations, candidates, args.asset_id, complete=complete, inventory_complete=inventory_complete, limitations=limitations)
        if args.logo:
            protected.append(args.logo)
        output = canonical_json(report) if args.format == "json" else render_csv(report) if args.format == "csv" else render_html(report, brand=args.brand, logo=args.logo)
        if args.output:
            save_report(args.output, output, force=args.force, protected_paths=protected)
        else:
            sys.stdout.write(output)
        if interrupted:
            return 130
        if not complete:
            return 2
        statuses = {result["status"] for result in report["results"]}
        if args.fail_on_finding and "potentially_affected" in statuses:
            return 1
        if args.fail_on_unknown and "unknown" in statuses:
            return 1
        return 0
    except ScanInputError as exc:
        sys.stderr.write("Assessment failed: " + str(exc) + "\n")
        return 2
    except (OSError, ValueError):
        sys.stderr.write("Assessment failed: invalid input, unavailable file, protected output, or report validation error.\n")
        return 2
    except KeyboardInterrupt:
        sys.stderr.write("Assessment interrupted before a complete report was produced.\n")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
