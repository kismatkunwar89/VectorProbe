import pytest

from handlers.nmap_handler import CommandResult, NmapHandler


def test_scan_targets_expands_multiple_targets(monkeypatch):
    handler = NmapHandler()
    executed = {}

    def fake_run(cmd):
        executed['cmd'] = cmd
        return CommandResult(command=" ".join(cmd), stdout="", stderr="", exit_code=0)

    monkeypatch.setattr(handler, "_run", fake_run)

    handler.scan_targets(targets="10.248.1.1,10.248.1.2 10.248.1.3")

    assert executed['cmd'][-3:] == [
        "10.248.1.1",
        "10.248.1.2",
        "10.248.1.3",
    ]


def test_scan_targets_requires_at_least_one_target():
    handler = NmapHandler()

    with pytest.raises(ValueError):
        handler.scan_targets(targets="  ,  ")
