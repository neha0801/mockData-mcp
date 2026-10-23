# Phase 4: QA test-data skill (not started)

Inputs: client, message type, test type (regression | load), volume, seed.
Scenario catalogue first, user confirmation, then a deterministic generator
script writes the data. The agent receives only a summary (paths, counts,
pass/fail) and never reads the output files.
