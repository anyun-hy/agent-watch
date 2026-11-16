#!/usr/bin/env python3
from pathlib import Path
source = (Path(__file__).resolve().parent.parent / "monitor/Sources/SwitcherStore.swift").read_text()
assert "SwitcherCommandRunner.run(args, input: input, setupProgress: channel)" in source
assert "defer { channel?.finish() }" in source
for retired in ("runAccountSwitchWithDNSRefresh", "pollDNSRefreshRequests", "awaitFreshDNSReceipt", "dnsRefreshToken"):
    assert retired not in source, f"retired UI DNS control path remains: {retired}"
print("PASS: account switch uses the common Rust command and bounded progress reader; no UI DNS rendezvous")
