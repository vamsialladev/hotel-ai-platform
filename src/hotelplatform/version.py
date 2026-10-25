"""Which code is running? "1.7.0+b111480": the app's version plus the git commit.

Streamlit Cloud deploys a git checkout, so the commit is read straight from `.git` (no git binary needed); Docker
images pass it as GIT_COMMIT at build time. Unknown parts are reported as "unknown", never guessed.
"""

import os
from pathlib import Path


def git_commit(root: str | Path = ".") -> str:
    if os.environ.get("GIT_COMMIT"):
        return os.environ["GIT_COMMIT"][:7]
    git = Path(root) / ".git"
    try:
        head = (git / "HEAD").read_text(encoding="utf-8").strip()
        if not head.startswith("ref:"):
            return head[:7]
        ref = head.split(" ", 1)[1].strip()
        ref_file = git / ref
        if ref_file.exists():
            return ref_file.read_text(encoding="utf-8").strip()[:7]
        packed = git / "packed-refs"
        if packed.exists():
            for line in packed.read_text(encoding="utf-8").splitlines():
                if line.endswith(" " + ref):
                    return line.split(" ", 1)[0][:7]
    except OSError:
        pass
    return "unknown"


def version_string(app_version: str, root: str | Path = ".") -> str:
    return f"{app_version}+{git_commit(root)}"
