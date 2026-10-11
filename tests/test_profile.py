import os
import subprocess
import sys


# Run subprocesses from the repository root, so that they import the
# pymerkle package under test regardless of the current directory
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_import_leaves_builtins_untouched():
    """
    Importing pymerkle used to define builtins.profile process-wide.
    """
    code = 'import builtins, pymerkle; print(hasattr(builtins, "profile"))'
    result = subprocess.run([sys.executable, '-c', code], cwd=ROOT,
        capture_output=True, text=True, check=True)

    assert result.stdout.strip() == 'False'


def test_profiler_decorator_honored():
    code = '\n'.join([
        'import builtins',
        'calls = []',
        'builtins.profile = lambda func: calls.append(func) or func',
        'import pymerkle',
        'assert calls, "profiler decorator not applied"',
    ])
    subprocess.run([sys.executable, '-c', code], cwd=ROOT, check=True)
