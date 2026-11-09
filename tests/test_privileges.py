"""
Tests for main.ensure_privileges(). These mock os.geteuid/os.execvp rather
than actually invoking sudo — there's no way to safely exercise a real
process-replacing exec() from inside a test, and no sandboxed CI
environment reliably has a passwordless sudo available anyway. What's
verified is the *decision logic*: escalate when not root, build the
correct argv, skip cleanly when already root or explicitly disabled.
"""
from unittest.mock import patch

import main


def test_skips_elevation_when_already_root():
    with patch("os.geteuid", return_value=0), patch("os.execvp") as mock_exec:
        main.ensure_privileges(no_elevate=False)
        mock_exec.assert_not_called()


def test_skips_elevation_when_no_elevate_flag_set():
    with patch("os.geteuid", return_value=1000), patch("os.execvp") as mock_exec:
        main.ensure_privileges(no_elevate=True)
        mock_exec.assert_not_called()


def test_elevates_via_sudo_with_correct_argv():
    fake_argv = ["main.py", "--target-host", "10.0.0.5"]
    with patch("os.geteuid", return_value=1000), \
         patch("os.execvp") as mock_exec, \
         patch("sys.argv", fake_argv), \
         patch("sys.executable", "/usr/bin/python3"):
        main.ensure_privileges(no_elevate=False)
        mock_exec.assert_called_once_with(
            "sudo", ["sudo", "-E", "/usr/bin/python3"] + fake_argv
        )


def test_missing_sudo_binary_exits_cleanly_instead_of_crashing():
    with patch("os.geteuid", return_value=1000), \
         patch("os.execvp", side_effect=FileNotFoundError):
        try:
            main.ensure_privileges(no_elevate=False)
            assert False, "expected SystemExit"
        except SystemExit as exc:
            assert exc.code == 1
