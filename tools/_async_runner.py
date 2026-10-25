"""
tools._async_runner – thin subprocess helpers used by bloodyad_tool.py
and autobloody_tool.py.

All public functions return the standard dict shape:
    {
        "success":    bool,
        "summary":    str,
        "findings":   list[str],
        "raw_output": str,
        "returncode": int,
        "stdout":     str,
        "stderr":     str,
    }
"""
from __future__ import annotations

import asyncio
import subprocess
from typing import Any, Sequence


# ---------------------------------------------------------------------------
# Synchronous helper (used in bloodyad_tool.py / autobloody_tool.py)
# ---------------------------------------------------------------------------

def run_sync(cmd: Sequence[str | Any], timeout: int = 180) -> dict:
    """Run *cmd* synchronously, capture output, return standard dict."""
    cmd_str = " ".join(str(c) for c in cmd)
    try:
        result = subprocess.run(
            [str(c) for c in cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        success = result.returncode == 0
        raw     = result.stdout
        if result.stderr:
            raw += "\n" + result.stderr
        findings = [ln for ln in result.stdout.splitlines() if ln.strip()]
        return {
            "success":    success,
            "summary":    f"[rc={result.returncode}] {cmd_str[:80]}",
            "findings":   findings,
            "raw_output": raw,
            "returncode": result.returncode,
            "stdout":     result.stdout,
            "stderr":     result.stderr,
        }
    except subprocess.TimeoutExpired:
        return {
            "success":    False,
            "summary":    f"Command timed out after {timeout}s: {cmd_str[:80]}",
            "findings":   [],
            "raw_output": f"TIMEOUT after {timeout}s",
            "returncode": -1,
            "stdout":     "",
            "stderr":     "",
        }
    except FileNotFoundError:
        return {
            "success":    False,
            "summary":    f"Command not found: {cmd[0]}",
            "findings":   [],
            "raw_output": f"FileNotFoundError: {cmd[0]}",
            "returncode": -1,
            "stdout":     "",
            "stderr":     "",
        }
    except Exception as exc:
        return {
            "success":    False,
            "summary":    f"Error running command: {exc}",
            "findings":   [],
            "raw_output": str(exc),
            "returncode": -1,
            "stdout":     "",
            "stderr":     "",
        }


# ---------------------------------------------------------------------------
# Async helpers (used in autobloody_tool.py)
# ---------------------------------------------------------------------------

async def launch(cmd: Sequence[str | Any],
                 timeout: int | None = None,
                 **kwargs) -> asyncio.subprocess.Process:
    """
    Launch *cmd* as an async subprocess.  Returns the Process object.
    Call ``fetch(proc, timeout=...)`` to collect the result.
    """
    proc = await asyncio.create_subprocess_exec(
        *[str(c) for c in cmd],
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        **kwargs,
    )
    return proc


async def fetch(proc: asyncio.subprocess.Process,
                timeout: int | None = None) -> dict:
    """
    Wait for *proc* (returned by ``launch``) and return the standard result dict.
    Terminates the process on timeout.
    """
    cmd_label = f"pid={proc.pid}"
    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        stdout = stdout_b.decode(errors="replace")
        stderr = stderr_b.decode(errors="replace")
        rc      = proc.returncode
        success = rc == 0
        raw     = stdout + ("\n" + stderr if stderr else "")
        findings = [ln for ln in stdout.splitlines() if ln.strip()]
        return {
            "success":    success,
            "summary":    f"[rc={rc}] {cmd_label}",
            "findings":   findings,
            "raw_output": raw,
            "returncode": rc,
            "stdout":     stdout,
            "stderr":     stderr,
        }
    except asyncio.TimeoutError:
        try:
            proc.terminate()
        except ProcessLookupError:
            pass
        return {
            "success":    False,
            "summary":    f"Process timed out: {cmd_label}",
            "findings":   [],
            "raw_output": "TIMEOUT",
            "returncode": -1,
            "stdout":     "",
            "stderr":     "",
        }
