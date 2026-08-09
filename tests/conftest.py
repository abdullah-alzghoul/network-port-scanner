"""
Makes the project root importable so `from scanner.x import y` works
when pytest is run from anywhere, without needing sys.path edits in
every individual test file.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))