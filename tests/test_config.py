"""TrafficConfig validation tests."""

import pytest

from trafficgoat.config import TrafficConfig, GeneratorConfig, ConfigError, parse_ports


class TestValidate:
    def test_defaults_valid(self):
        TrafficConfig().validate()

    def test_rate_too_low(self):
        c = TrafficConfig(rate=0)
        with pytest.raises(ConfigError, match="rate"):
            c.validate()

    def test_rate_too_high(self):
        c = TrafficConfig(rate=2_000_000)
        with pytest.raises(ConfigError, match="rate"):
            c.validate()

    def test_threads_bounds(self):
        TrafficConfig(threads=1).validate()
        TrafficConfig(threads=256).validate()
        with pytest.raises(ConfigError, match="threads"):
            TrafficConfig(threads=0).validate()
        with pytest.raises(ConfigError, match="threads"):
            TrafficConfig(threads=10_000).validate()

    def test_duration_zero_allowed(self):
        TrafficConfig(duration=0).validate()

    def test_duration_too_long(self):
        with pytest.raises(ConfigError, match="duration"):
            TrafficConfig(duration=99_999_999).validate()

    def test_invalid_port(self):
        c = TrafficConfig(ports="99999")
        with pytest.raises(ConfigError, match="port"):
            c.validate()

    def test_port_range(self):
        TrafficConfig(ports="1-1024").validate()
        TrafficConfig(ports="80,443,8080").validate()


class TestParsePorts:
    def test_single(self):
        assert parse_ports("80") == [80]

    def test_range(self):
        assert parse_ports("80-82") == [80, 81, 82]

    def test_csv(self):
        assert parse_ports("80,443,8080") == [80, 443, 8080]


class TestFromDict:
    def test_builds_generators(self):
        data = {
            "target": "192.168.1.1",
            "duration": 30,
            "generators": [
                {"type": "tcp_syn", "ports": "80,443", "rate": 200},
                {"type": "dns", "subtype": "mixed", "rate": 50},
            ],
        }
        cfg = TrafficConfig.from_dict(data)
        assert cfg.target == "192.168.1.1"
        assert cfg.duration == 30
        assert len(cfg.generators) == 2
        assert all(isinstance(g, GeneratorConfig) for g in cfg.generators)
        assert cfg.generators[0].type == "tcp_syn"

    def test_does_not_mutate_caller_dict(self):
        """Regression: from_dict used to pop 'generators' out of the input."""
        data = {"target": "10.0.0.1", "generators": [{"type": "udp"}]}
        TrafficConfig.from_dict(data)
        assert "generators" in data, "from_dict must not mutate the caller's dict"
        assert data["generators"] == [{"type": "udp"}]

    def test_unknown_keys_ignored(self):
        cfg = TrafficConfig.from_dict({"target": "10.0.0.1", "bogus_key": 123})
        assert cfg.target == "10.0.0.1"
        assert not hasattr(cfg, "bogus_key")


class TestDataclassFields:
    """Verify the auto_load / allow_public / enable_malicious fields exist
    (regression for the dynamic-attribute bug)."""

    def test_auto_load_defaults_to_medium(self):
        assert TrafficConfig().auto_load == "medium"

    def test_allow_public_default_false(self):
        assert TrafficConfig().allow_public is False

    def test_enable_malicious_default_false(self):
        assert TrafficConfig().enable_malicious is False
