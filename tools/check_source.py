"""Dependency-free checks for maintained source files; never inspect Claude data."""
import ast
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent
paths = [ROOT / 'README.md', *sorted(ROOT.glob('test_*.py')), Path(__file__).resolve()]
paths.extend(p for p in (ROOT / 'cc-clean').rglob('*') if p.is_file() and '__pycache__' not in p.parts)
for path in paths:
    text = path.read_text(encoding='utf-8')
    assert text.endswith('\n'), f'Missing final newline: {path.relative_to(ROOT)}'
    assert not any(line.rstrip() != line for line in text.splitlines()), f'Trailing whitespace: {path.relative_to(ROOT)}'
    if path.suffix == '.py':
        ast.parse(text, filename=str(path))
    if path.suffix == '.md':
        for destination in re.findall(r'\]\(([^)]+)\)', text):
            if '://' not in destination:
                assert (path.parent / destination.split('#')[0]).exists(), f'Broken reference: {path.relative_to(ROOT)}'
template = (ROOT / 'cc-clean/assets/report.html').read_text()
script = re.search(r'<script id="app">([\s\S]*?)</script>', template)[1]
result = subprocess.run(['node', '--check', '--input-type=commonjs'], input=script, text=True, capture_output=True)
assert result.returncode == 0, 'HTML JavaScript syntax check failed'
print(f'Format, Python/JavaScript syntax and Markdown links valid: {len(paths)} files')
