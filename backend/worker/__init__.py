"""Playwright worker-pool primitives.

This package splits the Playwright-heavy work out of the :8091 control
plane into a pool of subprocess workers. See backend/worker/dispatcher.py
for the parent-side API and backend/worker/__main__.py for the worker
entry point.

Gated by the `workers_enabled` config flag — when off, the existing
single-process session handler in routes/browser.py is used and this
package sits idle.
"""
