"""Shrink the installed sources: strip Python comments and blank runs,
JavaScript comments and indentation, CSS comments and whitespace, and
template indentation. Semantics are preserved; package.sh compiles the result."""
import io
import shutil
import sys
import tokenize
from pathlib import Path

KEEP_DIRS = ("templates", "static", "systemd")


def minify_python(source):
    lines = source.splitlines()
    protected = set()
    cuts = {}
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.end[0] > token.start[0]:
            protected.update(range(token.start[0], token.end[0] + 1))
        elif token.type == tokenize.COMMENT:
            row, column = token.start
            cuts[row] = min(cuts.get(row, column), column)
    out = []
    blank = False
    for number, line in enumerate(lines, 1):
        if number in protected:
            out.append(line)
            blank = False
            continue
        if number in cuts:
            line = line[:cuts[number]]
        line = line.rstrip()
        if not line:
            if not blank:
                out.append("")
            blank = True
            continue
        blank = False
        out.append(line)
    result = "\n".join(out) + "\n"
    compile(result, "<minified>", "exec")
    return result


def minify_html(source):
    lines = [line.strip() for line in source.splitlines()]
    return "\n".join(line for line in lines if line) + "\n"


def minify_js(source):
    out = []
    i, n = 0, len(source)
    in_template = False
    while i < n:
        c = source[i]
        if in_template:
            j = i
            while j < n and source[j] != "`":
                j += 2 if source[j] == "\\" else 1
            out.append(source[i:min(j + 1, n)])
            in_template = j >= n
            i = j + 1
            continue
        if c in "'\"":
            j = i + 1
            while j < n:
                if source[j] == "\\":
                    j += 2
                    continue
                if source[j] == c or source[j] == "\n":
                    break
                j += 1
            out.append(source[i:min(j + 1, n)])
            i = j + 1
            continue
        if c == "`":
            j = i + 1
            while j < n:
                if source[j] == "\\":
                    j += 2
                    continue
                if source[j] == "`":
                    break
                j += 1
            if j < n:
                out.append(source[i:j + 1])
                i = j + 1
            else:
                out.append(source[i:])
                in_template = True
                i = n
            continue
        if c == "/" and source[i:i + 2] == "//":
            while i < n and source[i] != "\n":
                i += 1
            continue
        if c == "/" and source[i:i + 2] == "/*":
            end = source.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        out.append(c)
        i += 1
    lines = []
    for line in "".join(out).splitlines():
        stripped = line.strip()
        if stripped:
            lines.append(stripped)
    return "\n".join(lines) + "\n"


def minify_css(source):
    out = []
    i, n = 0, len(source)
    while i < n:
        c = source[i]
        if c in "'\"":
            j = i + 1
            while j < n and source[j] != c:
                j += 2 if source[j] == "\\" else 1
            out.append(source[i:min(j + 1, n)])
            i = j + 1
            continue
        if source[i:i + 2] == "/*":
            end = source.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        if c.isspace():
            j = i
            while j < n and source[j].isspace():
                j += 1
            following = source[j] if j < n else ""
            if out and out[-1] not in "{};,:" and following not in "{};:,":
                out.append(" ")
            i = j
            continue
        if c == "}" and out and out[-1] == ";":
            out.pop()
        out.append(c)
        i += 1
    return "".join(out).strip() + "\n"


def write(path, text):
    with open(path, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)


def main():
    source, destination = Path(sys.argv[1]), Path(sys.argv[2])
    destination.mkdir(parents=True, exist_ok=True)
    for path in sorted(source.glob("*.py")):
        write(destination / path.name, minify_python(path.read_text(encoding="utf-8")))
    for name in KEEP_DIRS:
        for path in sorted((source / name).rglob("*")):
            if not path.is_file():
                continue
            target = destination / name / path.relative_to(source / name)
            target.parent.mkdir(parents=True, exist_ok=True)
            if path.suffix == ".css":
                write(target, minify_css(path.read_text(encoding="utf-8")))
            elif path.suffix == ".js":
                write(target, minify_js(path.read_text(encoding="utf-8")))
            elif path.suffix == ".html":
                write(target, minify_html(path.read_text(encoding="utf-8")))
            else:
                shutil.copyfile(path, target)


if __name__ == "__main__":
    main()
