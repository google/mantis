"""Authoritative path-boundary helpers for operator-supplied targets (INV-4).

The scan target is supplied by the operator but its *contents* — including any
symlinks it contains — are attacker controlled.

Two distinct classes of escape are closed here.

1. **Symlink dereferencing.** ``Path.resolve()`` silently dereferences every
   component, so a leaf-only ``is_symlink()`` check is not sufficient: a hostile
   checkout can ship ``repo/link`` -> ``../../..`` and have ``repo/link/sub``
   resolve to an arbitrary host directory while every leaf check passes. The
   invariant enforced is component-wise:

       No component of the target may be a symlink whose target lies outside
       the directory that lexically contains it.

   This refuses every attacker-plantable escape while tolerating the benign
   platform indirections that make absolute paths usable at all, such as macOS
   ``/var`` -> ``/private/var``, which stay within their containing directory.

2. **Normalization-order differentials.** Any check that inspects a *lexically
   normalized* path while the caller consumes a *symlink-resolved* path is
   bypassable, because ``normpath`` collapses ``link/..`` textually (erasing the
   component that was going to be checked) whereas ``realpath`` dereferences
   ``link`` first and then applies ``..`` to its target. ``repo/vendor/../.ssh``
   validated clean and resolved to ``~/.ssh`` under exactly this differential.
   Rather than try to keep two normalizers in agreement, ``..`` is refused
   outright and no lexical normalization is performed anywhere in this module.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Union

from core.llm_gateway import strip_terminal_control

# Components that are refused in an operator-supplied target. '..' creates the
# normalization differential described above; the empty and '.' components are
# dropped by pathlib itself and are harmless.
_REFUSED_PARTS = ("..",)


def install_root() -> Path:
    """The trusted Mantis 'reference' directory, derived from this module's location.

    SECURITY (INV-4): trusted resources (launcher scripts, workflow.json, the
    knowledge database) must be located relative to the installation, never by
    probing ``$CWD`` — a campaign is routinely launched from inside the untrusted
    checkout, where any probed name is attacker supplied.
    """
    return Path(__file__).resolve().parent.parent


def mantis_home() -> Path:
    """The Mantis installation root (the directory containing ``reference/``)."""
    env = os.environ.get("MANTIS_HOME")
    if env:
        candidate = Path(env).expanduser()
        if candidate.is_dir():
            return candidate.resolve()
    return install_root().parent


def workspace_dir() -> Path:
    """The trusted workspace directory used for campaign state and databases."""
    for candidate in (mantis_home() / "workspace", install_root() / "workspace"):
        if candidate.is_dir():
            return candidate.resolve()
    return (install_root() / "workspace").resolve()


def absolute_without_normalizing(path: Union[str, Path]) -> Path:
    """Makes a path absolute WITHOUT collapsing any ``..`` component.

    ``os.path.abspath`` normalizes, which is what creates the parser differential
    this module exists to avoid. ``pathlib`` joining preserves ``..`` verbatim
    (it only drops ``.`` and empty components, which carry no meaning).
    """
    raw = Path(path)
    if not raw.is_absolute():
        # $CWD is the operator's shell, not attacker input; only the operand is.
        raw = Path.cwd() / raw
    return raw


def find_traversal_component(path: Union[str, Path]) -> Optional[str]:
    """Returns the first refused traversal component ('..') in the path, if any."""
    for part in Path(path).parts:
        if part in _REFUSED_PARTS:
            return part
    return None


def find_escaping_symlink_component(
    path: Union[str, Path],
) -> Optional[tuple[Path, Path]]:
    """Finds the first path component that is a symlink escaping its own directory.

    Returns a ``(component, resolved_target)`` tuple for the offending component,
    or ``None`` when every component is safe.

    The walk is performed on the un-normalized absolute path, so no component can
    be erased before it is inspected. A ``..`` component is treated as an escape
    in its own right: this function must never lexically collapse one, because
    doing so is precisely the differential that defeats the check.
    """
    abs_path = absolute_without_normalizing(path)
    cur = Path(abs_path.anchor or os.sep)

    for part in abs_path.parts[1:]:
        if part in _REFUSED_PARTS:
            # Refused upstream by validate_scan_target; treated as an escape here
            # so that any other caller inherits the same fail-closed behaviour.
            return cur / part, Path(os.path.realpath(str(cur / part)))

        # Resolved identity of the directory that lexically contains this component.
        # Every prefix component has already been proven non-escaping, so resolving
        # here cannot itself be used to smuggle in an escape.
        parent_real = Path(os.path.realpath(str(cur)))
        cur = cur / part

        if os.path.islink(str(cur)):
            link_real = Path(os.path.realpath(str(cur)))
            try:
                link_real.relative_to(parent_real)
            except ValueError:
                return cur, link_real

    return None


def validate_scan_target(target: Union[str, Path]) -> tuple[Optional[Path], str]:
    """Validates and resolves an operator-supplied scan target.

    Enforces, in order:
      1. No ``..`` component (removes the normalization differential entirely).
      2. The leaf itself is not a symlink.
      3. No intermediate component is a symlink escaping its containing directory.
      4. The resolved target exists.

    Returns ``(resolved_path, "")`` on success or ``(None, error_message)``.
    The error message is control-character stripped: it echoes attacker-controlled
    path text back to a terminal, so it is an egress path like any other.
    """
    shown = strip_terminal_control(str(target))
    raw = absolute_without_normalizing(target)

    traversal = find_traversal_component(raw)
    if traversal is not None:
        return None, (
            f"Target '{shown}' contains a '{traversal}' component. Parent-directory "
            "traversal is refused for safety because it makes the path's meaning depend "
            "on whether symlinks are resolved before or after normalization; pass the "
            "real path instead."
        )

    if Path(target).is_symlink():
        return None, (
            f"Target '{shown}' is a symlink. Symlinked scan targets are refused for safety."
        )

    escaping = find_escaping_symlink_component(raw)
    if escaping is not None:
        component, link_real = escaping
        return None, (
            f"Target '{shown}' traverses symlinked path component "
            f"'{strip_terminal_control(str(component))}' which escapes to "
            f"'{strip_terminal_control(str(link_real))}'. Symlinked path components are "
            "refused for safety; pass the real path instead."
        )

    resolved = raw.resolve()
    if not resolved.exists():
        return None, f"Target '{shown}' does not exist."

    return resolved, ""


def validate_data_path(
    path: Union[str, Path], anchor: Optional[Path] = None
) -> tuple[Optional[Path], str]:
    """Validates a path Mantis will *open or create* (databases, state files).

    Unlike a scan target this path need not exist yet, so the containment check is
    applied to the deepest ancestor that does exist.

    Returns ``(path, "")`` or ``(None, error_message)``.
    """
    shown = strip_terminal_control(str(path))
    raw = absolute_without_normalizing(path)

    traversal = find_traversal_component(raw)
    if traversal is not None:
        return None, f"Refusing path '{shown}': '{traversal}' components are not permitted."

    if os.path.islink(str(raw)):
        return None, (
            f"Refusing path '{shown}': it is a symlink. A symlinked state file redirects "
            "writes to an arbitrary host file."
        )

    escaping = find_escaping_symlink_component(raw)
    if escaping is not None:
        component, link_real = escaping
        return None, (
            f"Refusing path '{shown}': it traverses symlinked component "
            f"'{strip_terminal_control(str(component))}' escaping to "
            f"'{strip_terminal_control(str(link_real))}'."
        )

    if anchor is not None:
        anchor_real = Path(os.path.realpath(str(anchor)))
        probe = raw
        while not probe.exists() and probe != probe.parent:
            probe = probe.parent
        probe_real = Path(os.path.realpath(str(probe)))
        try:
            probe_real.relative_to(anchor_real)
        except ValueError:
            return None, (
                f"Refusing path '{shown}': it resolves outside the permitted directory "
                f"'{anchor_real}'."
            )

    return raw, ""


def resolve_db_path(db_path: Union[str, Path], default_name: str = "knowledge.db") -> str:
    """Anchors and validates a SQLite database path before it is opened.

    SECURITY (INV-4): ``sqlite3.connect`` resolves a relative name against ``$CWD`` and
    happily follows a symlink, creating and writing to whatever it points at. A campaign
    runs with ``$CWD`` inside the untrusted checkout, so a repository shipping
    ``knowledge.db`` -> ``~/.zprofile`` turns every database write into an append of
    model-controlled text to a file the victim's shell executes at next login.

    Relative names are therefore anchored to the installation (never ``$CWD``), and every
    path — anchored or operator-supplied absolute — is refused if it is a symlink or
    traverses one.

    Raises:
        PermissionError: if the path is unsafe.
    """
    raw = str(db_path or "").strip()
    if not raw:
        return str(install_root() / default_name)

    candidate = Path(raw)
    if candidate.is_absolute():
        validated, err = validate_data_path(candidate)
    else:
        anchor = install_root()
        validated, err = validate_data_path(anchor / candidate, anchor=anchor)

    if validated is None:
        raise PermissionError(err)
    return str(validated)

