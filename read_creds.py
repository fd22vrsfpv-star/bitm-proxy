#!/usr/bin/env python3
"""Read encrypted credential store entries."""

import getpass
import json
import os
import sys

# Ensure the project root is on the Python path so 'backend' resolves
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Prompt for passphrase before any imports that depend on it
passphrase = getpass.getpass("Enter CREDENTIAL_PASSPHRASE: ")
os.environ["CREDENTIAL_PASSPHRASE"] = passphrase

from backend.store import JsonStore

NAMESPACES = ["sessions", "cookies", "credentials"]

found = False
for ns in NAMESPACES:
    store = JsonStore(ns)
    keys = store.list_keys()
    if not keys:
        continue
    found = True
    print(f"\n=== {ns} ({len(keys)} entries) ===")
    for k in keys:
        try:
            data = store.get(k)
            print(f"\n  [{k}]")
            print(json.dumps(data, indent=4, default=str))
        except Exception as e:
            print(f"\n  [{k}] ERROR: {e}")

if not found:
    print("\nNo entries found in any namespace.")
