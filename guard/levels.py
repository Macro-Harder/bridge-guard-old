import dataclasses

LEVEL_MIN = 0
LEVEL_MAX = 11


class LevelError(Exception):
    pass


@dataclasses.dataclass(frozen=True)
class Dependency:
    requires: str
    fallbacks: dict


@dataclasses.dataclass(frozen=True)
class Setting:
    name: str
    default: object
    depends_on: tuple = ()


@dataclasses.dataclass(frozen=True)
class Preset:
    level: int
    values: dict
    components: frozenset


@dataclasses.dataclass(frozen=True)
class Forcing:
    setting: str
    dependency: str
    value: object


@dataclasses.dataclass(frozen=True)
class Resolution:
    values: dict
    forced: tuple
    notifications: tuple
    manager_flags: tuple


def _fallbacks(value):
    return {level: value for level in range(LEVEL_MIN, LEVEL_MAX + 1)}


_SETTINGS = (
    Setting("logging_enabled", True),
    Setting("manager_review_enabled", True),
    Setting("scanner_enabled", True),
    Setting("fast_path_enabled", True),
    Setting("precedent_path_enabled", True,
            (Dependency("fast_path_enabled", _fallbacks(True)),)),
    Setting("ledger_on", False),
    Setting("absolute_trust_enabled", False,
            (Dependency("logging_enabled", _fallbacks(True)),
             Dependency("absolute_trust_daily_byte_cap",
                        _fallbacks(10485760)))),
    Setting("size_cap_bytes", 10485760),
    Setting("request_rate_cap_per_hour", 20),
    Setting("absolute_trust_daily_byte_cap", 10485760),
)

_REGISTRY = {s.name: s for s in _SETTINGS}


def settings():
    return _SETTINGS


def setting(name):
    try:
        return _REGISTRY[name]
    except KeyError:
        raise LevelError("unknown setting: %r" % (name,)) from None


def _check_level(level):
    if isinstance(level, bool) or not isinstance(level, int):
        raise LevelError("level must be an integer, got %r" % (level,))
    if not LEVEL_MIN <= level <= LEVEL_MAX:
        raise LevelError("level %d outside %d..%d"
                         % (level, LEVEL_MIN, LEVEL_MAX))


def _engaged(value):
    return value is not False and value is not None


def preset_for(level):
    _check_level(level)
    values = {}
    for s in _SETTINGS:
        if level == 0:
            if s.name == "logging_enabled":
                values[s.name] = True
            elif isinstance(s.default, bool):
                values[s.name] = False
            else:
                values[s.name] = None
        elif isinstance(s.default, bool):
            values[s.name] = s.name != "absolute_trust_enabled"
        else:
            values[s.name] = s.default
    components = frozenset({"monitor-agent"}) if level == 11 \
        else frozenset()
    return Preset(level=level, values=values, components=components)


def resolve(level, overrides=None, advanced=None):
    preset = preset_for(level)
    values = dict(preset.values)
    for mapping in (advanced, overrides):
        if not mapping:
            continue
        for name, value in mapping.items():
            setting(name)
            values[name] = value
    queue = [name for name in values
             if _engaged(values[name])
             and not _engaged(preset.values[name])]
    forced = []
    seen = set(queue)
    while queue:
        name = queue.pop(0)
        for dep in setting(name).depends_on:
            if _engaged(values[dep.requires]):
                continue
            target = setting(dep.requires)
            if level in dep.fallbacks:
                value = dep.fallbacks[level]
            elif isinstance(target.default, bool):
                value = True
            else:
                value = target.default
            values[dep.requires] = value
            forced.append(Forcing(setting=name, dependency=dep.requires,
                                  value=value))
            if dep.requires not in seen:
                seen.add(dep.requires)
                queue.append(dep.requires)
    notifications = tuple(
        "%s requires %s: %s was forced on (set to %r); "
        "the dependency cannot stay off while %s is on"
        % (f.setting, f.dependency, f.dependency, f.value, f.setting)
        for f in forced)
    manager_flags = tuple(
        "manager flag: %s was forced on because %s depends on it"
        % (f.dependency, f.setting)
        for f in forced)
    return Resolution(values=values, forced=tuple(forced),
                      notifications=notifications,
                      manager_flags=manager_flags)
