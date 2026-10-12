"""Custom mode - user-defined traffic patterns via YAML config."""

from trafficgoat.config import TrafficConfig
from trafficgoat.engine import TrafficEngine
from trafficgoat.stats import StatsCollector
from trafficgoat.generators import GENERATORS


class CustomMode:
    """User-defined traffic patterns loaded from YAML configuration."""

    name = "custom"
    description = "Custom traffic pattern from YAML configuration file"

    @staticmethod
    def configure(config: TrafficConfig, engine: TrafficEngine, stats: StatsCollector):
        """Configure engine from user-defined generator list in config."""
        if not config.generators:
            stats.log("Custom mode requires generators in config file (-c config.yaml)")
            stats.log("No generators configured, nothing to do")
            return

        stats.log(f"Custom mode: Loading {len(config.generators)} generator(s) from config")

        for gen_config in config.generators:
            # Inherit target from main config if not set per-generator
            if not gen_config.target:
                gen_config.target = config.target
            if gen_config.duration == 60 and config.duration != 60:
                gen_config.duration = config.duration

            gen_type = gen_config.type.lower()
            gen_class = GENERATORS.get(gen_type)

            if gen_class is None:
                available = ", ".join(sorted(set(GENERATORS.keys())))
                stats.log(f"Unknown generator type '{gen_type}'. Available: {available}")
                continue

            generator = gen_class(gen_config, stats, config.dry_run)
            engine.add_generator(generator)
            stats.log(f"  Added: {generator.name} (rate={gen_config.rate}, weight={gen_config.weight})")
