"""Native acceptance and launch diagnostics."""
import json
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path
import pytest
from hermes_cli import kanban_db as kb
from hermes_cli import kanban_db_dispatch as kbd
from hermes_cli.kanban_db_connect import connect
from tests.hermes_cli.test_kanban_pr_acceptance import github
from tests.waiting import wait_until


def make_task(task_id="t_g1", assignee="elias"):
    return kb.Task(
        id=task_id, title="proof task", body=None, assignee=assignee,
        status="running", priority=0, created_by="test", created_at=1,
        started_at=None, completed_at=None, workspace_kind="dir",
        workspace_path=None, claim_lock="lock", claim_expires=None,
        tenant=None, current_run_id=1,
    )


def persist_receipt(outcome_data, tmp_path=None):
    cur = Path.cwd()
    dest = Path(tmp_path) if tmp_path else cur
    while True:
        if (cur / "sandbox-mount-manifest.json").exists():
            dest = cur
            break
        if cur.parent == cur:
            break
        cur = cur.parent
    out_path = dest / f"factory-proof-{outcome_data['proof']}.json"
    if out_path.exists():
        raise FileExistsError(str(out_path))
    out_path.write_text(json.dumps(outcome_data, indent=2), encoding="utf-8")
    return outcome_data


def read_json_lines(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.mark.platforms("linux")
def test_b1_contract_binding_and_evidence(github, tmp_path):
    gh_bin = Path(shutil.which("gh"))
    gh_real = gh_bin.parent / "gh-real"
    if not gh_real.exists():
        gh_bin.rename(gh_real)
    gh_log = gh_bin.parent / "gh_calls.jsonl"
    wrapper_code = (
        f"#!{sys.executable}\nimport json, os, sys\n"
        f"fd = os.open({str(gh_log)!r}, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)\n"
        f"with open(fd, 'a', encoding='utf-8') as f:\n"
        f"    f.write(json.dumps(sys.argv) + '\\n')\n"
        f"os.execv({str(gh_real)!r}, sys.argv)\n"
    )
    gh_bin.write_text(wrapper_code, encoding="utf-8")
    gh_bin.chmod(0o755)
    assert shutil.which("gh") == str(gh_bin)

    with connect() as conn:
        github.update(conclusion="pending", head="a" * 40)
        t_bind = kb.create_task(conn, title="t_bind", completion_contract="acme/repo")
        ok1 = kb.complete_task(conn, t_bind, result="done", metadata={"published_pr": "https://github.com/acme/repo/pull/7"})
        assert not ok1
        task_bind = kb.get_task(conn, t_bind)
        assert task_bind.status != "done"
        assert task_bind.completion_contract == "https://github.com/acme/repo/pull/7"

        github.update(conclusion="success")
        ok2 = kb.complete_task(conn, t_bind, result="done", metadata={"published_pr": "https://github.com/acme/repo/pull/8"})
        assert not ok2
        task_bind2 = kb.get_task(conn, t_bind)
        assert task_bind2.status != "done"
        assert task_bind2.completion_contract == "https://github.com/acme/repo/pull/7"

        github.update(conclusion="success", stale=True)
        t_stale = kb.create_task(conn, title="t_stale", completion_contract="acme/repo")
        assert not kb.complete_task(conn, t_stale, result="done", metadata={"published_pr": "https://github.com/acme/repo/pull/7"})
        assert kb.get_task(conn, t_stale).status != "done"
        r_stale = [json.loads(r[0]) for r in conn.execute("SELECT payload FROM task_events WHERE task_id=? AND kind='pr_acceptance'", (t_stale,))]
        assert len(r_stale) == 1 and r_stale[0]["classification"] == "stale"
        github.pop("stale", None)

        github.update(conclusion="pending")
        t_pend = kb.create_task(conn, title="t_pend", completion_contract="acme/repo")
        assert not kb.complete_task(conn, t_pend, result="done", metadata={"published_pr": "https://github.com/acme/repo/pull/7"})
        assert kb.get_task(conn, t_pend).status != "done"
        r_pend = [json.loads(r[0]) for r in conn.execute("SELECT payload FROM task_events WHERE task_id=? AND kind='pr_acceptance'", (t_pend,))]
        assert len(r_pend) == 1 and r_pend[0]["classification"] == "pending"

        github.update(conclusion="success", missing=True)
        t_miss = kb.create_task(conn, title="t_miss", completion_contract="acme/repo")
        assert not kb.complete_task(conn, t_miss, result="done", metadata={"published_pr": "https://github.com/acme/repo/pull/7"})
        assert kb.get_task(conn, t_miss).status != "done"
        r_miss = [json.loads(r[0]) for r in conn.execute("SELECT payload FROM task_events WHERE task_id=? AND kind='pr_acceptance'", (t_miss,))]
        assert len(r_miss) == 1 and r_miss[0]["classification"] == "missing"
        github.pop("missing", None)

        github.update(conclusion="success")
        t_succ = kb.create_task(conn, title="t_succ", completion_contract="acme/repo")
        assert kb.complete_task(conn, t_succ, result="done", metadata={"published_pr": "https://github.com/acme/repo/pull/7"})
        assert kb.get_task(conn, t_succ).status == "done"
        r_succ = [json.loads(r[0]) for r in conn.execute("SELECT payload FROM task_events WHERE task_id=? AND kind='pr_acceptance'", (t_succ,))]
        assert len(r_succ) == 1 and r_succ[0]["classification"] == "success"

        calls_before = len(read_json_lines(gh_log))
        assert calls_before > 0
        t_ghost = kb.create_task(conn, title="t_ghost", completion_contract="acme/repo", assignee="ghost")
        assert not kb.complete_task(conn, t_ghost, result="done", metadata={"published_pr": "https://github.com/acme/repo/pull/7"})
        task_ghost = kb.get_task(conn, t_ghost)
        assert task_ghost.status != "done"
        assert task_ghost.completion_contract == "https://github.com/acme/repo/pull/7"
        assert task_ghost.last_failure_error
        r_ghost = [json.loads(r[0]) for r in conn.execute("SELECT payload FROM task_events WHERE task_id=? AND kind='pr_acceptance'", (t_ghost,))]
        assert len(r_ghost) == 1 and r_ghost[0]["classification"] == "auth"
        assert len(read_json_lines(gh_log)) == calls_before

    persist_receipt({"proof": "B1", "status": "PASSED", "baseline": "71d", "bound_pr": "https://github.com/acme/repo/pull/7"}, tmp_path=tmp_path)


@pytest.mark.platforms("linux")
def test_b2_direct_publication_diagnostic(tmp_path):
    repo_dir, bare_dir = tmp_path / "repo", tmp_path / "bare.git"
    repo_dir.mkdir()
    real_git = shutil.which("git") or "/usr/bin/git"
    subprocess.run([real_git, "init"], cwd=str(repo_dir), check=True, timeout=30, capture_output=True)
    subprocess.run([real_git, "config", "user.name", "Dummy User"], cwd=str(repo_dir), check=True, timeout=30, capture_output=True)
    subprocess.run([real_git, "config", "user.email", "dummy@example.com"], cwd=str(repo_dir), check=True, timeout=30, capture_output=True)
    (repo_dir / "proof.txt").write_text("proof content\n", encoding="utf-8")
    subprocess.run([real_git, "add", "."], cwd=str(repo_dir), check=True, timeout=30, capture_output=True)
    subprocess.run([real_git, "commit", "-m", "proof init"], cwd=str(repo_dir), check=True, timeout=30, capture_output=True)
    subprocess.run([real_git, "init", "--bare", str(bare_dir)], check=True, timeout=30, capture_output=True)
    subprocess.run([real_git, "remote", "add", "origin", str(bare_dir)], cwd=str(repo_dir), check=True, timeout=30, capture_output=True)

    shim_bin = tmp_path / "bin"
    shim_bin.mkdir()
    git_log, gh_log = tmp_path / "git_log.jsonl", tmp_path / "gh_log.jsonl"
    git_shim = (
        f"#!{sys.executable}\nimport json, os, sys\n"
        f"if 'push' in sys.argv[1:]:\n"
        f"    fd = os.open({str(git_log)!r}, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)\n"
        f"    with open(fd, 'a', encoding='utf-8') as f:\n"
        f"        f.write(json.dumps(sys.argv) + '\\n'); f.flush(); os.fsync(f.fileno())\n"
        f"    sys.exit(0)\n"
        f"os.execv({str(real_git)!r}, sys.argv)\n"
    )
    (shim_bin / "git").write_text(git_shim, encoding="utf-8")
    (shim_bin / "git").chmod(0o755)

    gh_shim = (
        f"#!{sys.executable}\nimport json, os, sys\n"
        f"if 'pr' in sys.argv[1:] and 'create' in sys.argv[1:]:\n"
        f"    fd = os.open({str(gh_log)!r}, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)\n"
        f"    with open(fd, 'a', encoding='utf-8') as f:\n"
        f"        f.write(json.dumps(sys.argv) + '\\n'); f.flush(); os.fsync(f.fileno())\n"
        f"    print('https://github.com/acme/repo/pull/7')\n"
        f"sys.exit(0)\n"
    )
    (shim_bin / "gh").write_text(gh_shim, encoding="utf-8")
    (shim_bin / "gh").chmod(0o755)

    env = dict(os.environ)
    env["PATH"] = str(shim_bin) + os.pathsep + env.get("PATH", "")
    p_git = subprocess.run(["git", "push", "origin", "main"], cwd=str(repo_dir), env=env, check=True, timeout=30, capture_output=True, text=True)
    p_gh = subprocess.run(["gh", "pr", "create", "--title", "proof", "--body", "body"], cwd=str(repo_dir), env=env, check=True, timeout=30, capture_output=True, text=True)
    assert p_git.returncode == 0 and p_gh.returncode == 0
    assert "https://github.com/acme/repo/pull/7" in p_gh.stdout

    git_rows, gh_rows = read_json_lines(git_log), read_json_lines(gh_log)
    assert len(git_rows) >= 1 and "push" in git_rows[0]
    assert len(gh_rows) >= 1 and "pr" in gh_rows[0] and "create" in gh_rows[0]

    persist_receipt({
        "proof": "B2", "status": "REPRODUCED", "baseline": "71d",
        "finding": "factory does not intervene in this direct subprocess",
        "limitation": "direct fixture process does NOT prove through native worker",
        "git_push": True, "gh_pr_create": True,
    }, tmp_path=tmp_path)


@pytest.mark.platforms("linux")
def test_g1_native_default_spawn_pins_and_metadata(monkeypatch, tmp_path):
    home = tmp_path / "home"
    profile = home / "profiles" / "elias"
    profile.mkdir(parents=True)
    profile.joinpath("config.yaml").write_text("{}\n", encoding="utf-8")
    home.joinpath("config.yaml").write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(home))

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    board = "test_board"
    dump_path = tmp_path / "g1_dump.json"

    stub_bin = tmp_path / "bin"
    stub_bin.mkdir()
    stub_code = (
        f"#!{sys.executable}\nimport json, os, sys\n"
        f"keys = ['HERMES_KANBAN_TASK', 'HERMES_KANBAN_WORKSPACE', 'HERMES_KANBAN_DB', 'HERMES_KANBAN_BOARD', 'HERMES_KANBAN_WORKSPACES_ROOT', 'TERMINAL_CWD', 'HERMES_HOME', 'HERMES_PROFILE']\n"
        f"env_data = {{k: os.environ[k] for k in keys if k in os.environ}}\n"
        f"ns = {{n: os.stat(f'/proc/self/ns/{{n}}').st_ino for n in ('mnt', 'pid', 'user') if os.path.exists(f'/proc/self/ns/{{n}}')}}\n"
        f"mounts = []\n"
        f"if os.path.exists('/proc/self/mountinfo'):\n"
        f"    with open('/proc/self/mountinfo', 'r', encoding='utf-8') as f:\n"
        f"        mounts = [l.strip() for l in f.readlines()[:5]]\n"
        f"out = {{'argv': sys.argv, 'env': env_data, 'ns': ns, 'mounts': mounts, 'pid': os.getpid()}}\n"
        f"dump = {str(dump_path)!r}\n"
        f"tmp = dump + '.tmp.' + str(os.getpid())\n"
        f"fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)\n"
        f"with open(fd, 'w', encoding='utf-8') as f:\n"
        f"    f.write(json.dumps(out))\n"
        f"    f.flush()\n"
        f"    os.fsync(f.fileno())\n"
        f"os.replace(tmp, dump)\n"
        f"sys.exit(0)\n"
    )
    (stub_bin / "hermes").write_text(stub_code, encoding="utf-8")
    (stub_bin / "hermes").chmod(0o755)
    monkeypatch.setenv("PATH", str(stub_bin) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("HERMES_BIN", str(stub_bin / "hermes"))

    task = make_task()
    pid = kbd._default_spawn(task, str(workspace), board=board)
    assert pid is not None
    try:
        data = wait_until(lambda: json.loads(dump_path.read_text(encoding="utf-8")) if dump_path.exists() and dump_path.stat().st_size > 0 else None, timeout=10, what="hermes stub run")
    finally:
        try:
            wait_until(lambda: os.waitpid(pid, os.WNOHANG)[0] == pid, timeout=10, what="hermes stub reap")
        except AssertionError:
            os.kill(pid, signal.SIGTERM)
            try:
                wait_until(lambda: os.waitpid(pid, os.WNOHANG)[0] == pid, timeout=5, what="hermes stub reap after SIGTERM")
            except AssertionError:
                os.kill(pid, signal.SIGKILL)
                wait_until(lambda: os.waitpid(pid, os.WNOHANG)[0] == pid, timeout=5, what="hermes stub reap after SIGKILL")

    observed_env = data["env"]
    assert observed_env["HERMES_KANBAN_TASK"] == task.id
    assert observed_env["HERMES_KANBAN_WORKSPACE"] == str(workspace)
    assert observed_env["TERMINAL_CWD"] == str(workspace)
    assert observed_env["HERMES_KANBAN_DB"] == str(kb.kanban_db_path(board=board))
    assert observed_env["HERMES_KANBAN_BOARD"] == board

    observed_argv = data["argv"]
    assert "hermes" in observed_argv[0]
    assert "-p" in observed_argv and "elias" in observed_argv
    assert "chat" in observed_argv

    persist_receipt({
        "proof": "G1", "status": "CAPTURED", "baseline": "71d",
        "observed_argv": observed_argv, "has_bwrap": any("bwrap" in a for a in observed_argv),
        "ns_inodes": data.get("ns", {}), "mountinfo_sample_len": len(data.get("mounts", [])),
        "disclaimer": "absence of bwrap does NOT claim unconfined if systemd wrappers are possible; G1 is not G2 trusted harness",
    }, tmp_path=tmp_path)
