from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import pytest

from hermes_cli import kanban_db as kb
from hermes_cli import kanban_db_boards as kbb
from hermes_cli import kanban_db_connect as kbc

from agent.delegation_context import DELEGATED_CHILD_ENV_MARKER


def find_receipt_dir(fallback: Path) -> Path:
    current = Path.cwd().resolve()
    for candidate in (current, *current.parents):
        if (candidate / "sandbox-mount-manifest.json").is_file():
            return candidate
    return fallback


def test_kanban_cross_project_isolation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home_dir = tmp_path / "hermes_home"
    home_dir.mkdir(parents=True, exist_ok=True)
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    sibling_file = tmp_path / "sibling" / "disposable_sibling.txt"
    sibling_file.parent.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("HERMES_HOME", str(home_dir))
    monkeypatch.setenv("HERMES_KANBAN_HOME", str(home_dir))
    base_env = os.environ.copy()
    for key in list(base_env.keys()):
        if key.startswith("HERMES_KANBAN_") or key == DELEGATED_CHILD_ENV_MARKER:
            base_env.pop(key, None)
    base_env["HERMES_HOME"] = str(home_dir)
    base_env["HERMES_KANBAN_HOME"] = str(home_dir)
    base_env["HERMES_DIR"] = str(home_dir)
    candidate_root = Path(kb.__file__).resolve().parents[1]
    base_env["PYTHONPATH"] = str(candidate_root)

    kbb.create_board("first")
    kbb.create_board("second")
    first_db = kb.kanban_db_path(board="first")
    second_db = kb.kanban_db_path(board="second")

    conn1 = kbc.connect(db_path=first_db)
    conn2 = kbc.connect(db_path=second_db)
    assert conn1.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 0
    assert conn2.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 0
    conn1.close()
    conn2.close()

    c1_env = base_env.copy()
    c1_env["HERMES_KANBAN_TASK"] = "task-pinned-witness"
    c1_env["HERMES_KANBAN_BOARD"] = "first"
    c1_env["HERMES_KANBAN_DB"] = str(first_db)

    c1_code = "\n".join([
        "import sys",
        "from pathlib import Path",
        "from hermes_cli import kanban_db as kb",
        "from hermes_cli import kanban_db_connect as kbc",
        f"assert Path(kb.__file__).resolve() == Path({str(candidate_root)!r}) / 'hermes_cli' / 'kanban_db.py'",
        f"assert Path(kbc.__file__).resolve() == Path({str(candidate_root)!r}) / 'hermes_cli' / 'kanban_db_connect.py'",
        "try:",
        "    conn = kbc.connect(board='second')",
        "    tid = kb.create_task(conn, title='witness-card-c1')",
        "    conn.close()",
        "    print(f'CREATED:{tid}')",
        "except PermissionError as exc:",
        "    print(f'REFUSED:{exc}')",
    ])
    res1 = subprocess.run(
        [sys.executable, "-c", c1_code],
        env=c1_env,
        cwd=workspace_dir,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert res1.returncode == 0, f"C1 child must exit zero: {res1.stderr}"

    conn1 = kbc.connect(db_path=first_db)
    conn2 = kbc.connect(db_path=second_db)
    t1 = [r["title"] for r in conn1.execute("SELECT title FROM tasks").fetchall()]
    t2 = [r["title"] for r in conn2.execute("SELECT title FROM tasks").fetchall()]
    conn1.close()
    conn2.close()

    created = res1.stdout.startswith("CREATED:")
    refused = res1.stdout.startswith("REFUSED:")
    assert created != refused, f"C1 must report exactly one of CREATED/REFUSED: {res1.stdout!r}"

    if created:
        if "witness-card-c1" in t2:
            c1_outcome = "REPRODUCED"
            assert t1 == [] and t2 == ["witness-card-c1"], f"REPRODUCED must be first=0 second=1: {t1!r} {t2!r}"
        else:
            c1_outcome = "PINNED"
            assert t1 == ["witness-card-c1"] and t2 == [], f"PINNED must be first=1 second=0: {t1!r} {t2!r}"
    else:
        c1_outcome = "REFUSED"
        assert t1 == [] and t2 == [], f"REFUSED must witness zero tasks: {t1!r} {t2!r}"

    c23_env = base_env.copy()
    c23_env[DELEGATED_CHILD_ENV_MARKER] = str(home_dir)
    sibling_str = str(sibling_file)
    c23_code = "\n".join([
        "import errno",
        "import sys",
        "from pathlib import Path",
        "from hermes_cli import kanban_db_connect as kbc",
        f"assert Path(kbc.__file__).resolve() == Path({str(candidate_root)!r}) / 'hermes_cli' / 'kanban_db_connect.py'",
        "conn = kbc.connect(board='first')",
        "try:",
        "    with kbc.write_txn(conn):",
        "        pass",
        "    print('C2:ALLOWED')",
        "except PermissionError as exc:",
        "    print(f'C2:REFUSED_PERMISSION_ERROR:{exc}')",
        "finally:",
        "    conn.close()",
        f"sibling = Path({sibling_str!r})",
        "try:",
        "    sibling.write_text('probe_ok', encoding='utf-8')",
        "    if sibling.read_text(encoding='utf-8') == 'probe_ok':",
        "        print('C3:ALLOWED')",
        "    else:",
        "        print('C3:MISMATCH')",
        "except OSError as exc:",
        "    if isinstance(exc, PermissionError) or exc.errno in (errno.EACCES, errno.EPERM, errno.EROFS):",
        "        print(f'C3:REFUSED:{type(exc).__name__}')",
        "    else:",
        "        raise",
    ])
    res23 = subprocess.run(
        [sys.executable, "-c", c23_code],
        env=c23_env,
        cwd=workspace_dir,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert res23.returncode == 0, f"C23 child must exit zero: {res23.stderr}"

    assert "C2:REFUSED_PERMISSION_ERROR" in res23.stdout, f"kbc.write_txn must refuse: {res23.stdout}"
    c2_status = "REFUSED_PERMISSION_ERROR"
    c3_readback = False
    if "C3:ALLOWED" in res23.stdout:
        c3_status = "ALLOWED"
        c3_readback = sibling_file.read_text(encoding="utf-8") == "probe_ok"
        assert c3_readback, "Native readback must equal probe_ok when C3 allowed"
    elif "C3:REFUSED" in res23.stdout:
        c3_status = "REFUSED"
        assert not sibling_file.exists(), "Refused C3 must leave no native file"
    else:
        pytest.fail(f"C3 failed to record allowed or refused: {res23.stdout}")

    receipt_dir = find_receipt_dir(tmp_path)
    receipt_path = receipt_dir / "kanban_cross_project_isolation_receipt.json"
    receipt_payload = {
        "c1_outcome": c1_outcome,
        "c1_first_board_count": len(t1),
        "c1_second_board_count": len(t2),
        "c1_returncode": res1.returncode,
        "c2_status": c2_status,
        "c23_returncode": res23.returncode,
        "c3_status": c3_status,
        "c3_readback_probe_ok": c3_readback,
        "c3_scope": "fenced_workspace_cwd_not_os_boundary",
        "c3_proves_factory_spawn_os_boundary": False,
        "witness_title": "witness-card-c1",
    }
    receipt_path.write_text(json.dumps(receipt_payload, indent=2), encoding="utf-8")
    assert receipt_path.is_file()
