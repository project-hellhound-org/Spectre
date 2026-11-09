"""
Tests for ScapyCollector.start()/stop()/swap_target(). AsyncSniffer needs
a raw socket (root + a real interface), which isn't available in this
environment, so these tests patch it with a lightweight fake that tracks
start/stop calls — what's being verified is the orchestration logic
(does swap actually stop the old sniffer, apply the new scope, and start
a new one with the updated filter), not scapy's own sniffing behavior.
"""
from unittest.mock import patch, MagicMock

from core.target import TargetScope
from collector.scapy_collector import ScapyCollector


def make_collector(scope):
    return ScapyCollector(on_event=lambda e: None, target_scope=scope)


def test_start_creates_and_starts_sniffer():
    collector = make_collector(TargetScope(hosts=["10.0.0.5"]))
    with patch("collector.scapy_collector.AsyncSniffer") as MockSniffer:
        instance = MagicMock()
        MockSniffer.return_value = instance

        collector.start()

        MockSniffer.assert_called_once()
        _, kwargs = MockSniffer.call_args
        assert kwargs["filter"] == "((udp port 53) or (tcp port 53)) and (host 10.0.0.5)"
        instance.start.assert_called_once()
        assert collector.is_running()


def test_start_is_idempotent():
    collector = make_collector(TargetScope())
    with patch("collector.scapy_collector.AsyncSniffer") as MockSniffer:
        MockSniffer.return_value = MagicMock()
        collector.start()
        collector.start()  # second call should be a no-op
        MockSniffer.assert_called_once()


def test_stop_tears_down_sniffer():
    collector = make_collector(TargetScope())
    with patch("collector.scapy_collector.AsyncSniffer") as MockSniffer:
        instance = MagicMock()
        MockSniffer.return_value = instance
        collector.start()
        collector.stop()
        instance.stop.assert_called_once()
        assert not collector.is_running()


def test_swap_target_stops_old_and_starts_new_with_updated_filter():
    original_scope = TargetScope(hosts=["10.0.0.5"])
    collector = make_collector(original_scope)

    with patch("collector.scapy_collector.AsyncSniffer") as MockSniffer:
        first_instance = MagicMock()
        second_instance = MagicMock()
        MockSniffer.side_effect = [first_instance, second_instance]

        collector.start()
        assert MockSniffer.call_args_list[0][1]["filter"] == \
            "((udp port 53) or (tcp port 53)) and (host 10.0.0.5)"

        new_scope = TargetScope(domains=["fitgirl-repacks.site"])
        collector.swap_target(new_scope)

        first_instance.stop.assert_called_once()
        second_instance.start.assert_called_once()
        # domain-only scope -> no BPF host clause, per the design constraint
        assert MockSniffer.call_args_list[1][1]["filter"] == "((udp port 53) or (tcp port 53))"

        # the ORIGINAL scope object was mutated in place, not replaced —
        # anything (e.g. the dashboard) holding a reference to it sees the change
        assert original_scope.matches(domain="fitgirl-repacks.site")
        assert collector.target_scope is original_scope


def test_swap_target_when_not_running_does_not_start_capture():
    """Swapping the target before capture has started shouldn't
    spontaneously start it — only start()/stop() should control that."""
    collector = make_collector(TargetScope(hosts=["10.0.0.5"]))
    with patch("collector.scapy_collector.AsyncSniffer") as MockSniffer:
        collector.swap_target(TargetScope(domains=["example.com"]))
        MockSniffer.assert_not_called()
        assert not collector.is_running()
        assert collector.target_scope.matches(domain="example.com")
