import copy
import dataclasses

DESIGN_REVISION = "bg-2026-11-08.13"
SUPPORTED_FORMAT_VERSIONS = (1,)


class ManifestError(ValueError):
    pass


class HandshakeRefused(ManifestError):
    pass


class VersionMismatch(HandshakeRefused):
    pass


class LevelMismatch(HandshakeRefused):
    pass


_PER_SIDE = {
    "allowed_roots": [],
    "staging_slots": 5,
    "outstanding_send_slots": 2,
    "receipt_ask_delay_s": 300,
    "receipt_escalation_window_s": 3600,
    "working_on_it_cap": 3,
    "heartbeat_period_s": 30,
    "heartbeat_miss_count": 3,
    "reconciliation_interval_s": 900,
    "gate_pass_expiry_s": 900,
    "list_entry_expiry_days": 90,
    "emergency_intro_key_window_s": 604800,
    "initiation_token_expiry_s": 3600,
    "successor_veto_window_s": 259200,
    "staged_copy_ttl_s": 3600,
    "quarantine_retention_days": 90,
    "precedent_expiry_days": 30,
    "precedent_cap": 25,
    "precedent_staleness_bound_s": 604800,
    "case_deadline_s": 259200,
    "digest_period": "daily",
    "boss_alert_deadline_s": 3600,
    "ack_deadline_s": 900,
    "resync_flap_window_s": 3600,
    "flap_escalation_count": 5,
    "flap_budget_count": 5,
    "flap_budget_duty_deadline_s": 1209600,
    "flap_escalation_window_s": 86400,
    "flap_forgiven_resyncs": 0,
    "flap_forgiven_events": 0,
    "flap_clean_bound_s": 3600,
    "adjudication_reprompt_s": 604800,
    "adjudication_escalation_s": 1209600,
    "adjudication_terminal_bound_s": 2592000,
    "retirement_silence_s": 2592000,
    "lift_min_interval_s": 86400,
    "restoration_cap_s": 604800,
    "health_ack_window_s": 14400,
    "quiet_hours": "22:00–07:00 local",
    "realert_cap": 3,
    "realert_interval_s": 3600,
    "security_realert_interval_s": 21600,
    "balance_exchange_schedule": "daily",
    "volume_event_schedule": "hourly",
    "volume_counts_exchange_bound_s": 3600,
    "volume_threshold_requests": 500,
    "volume_threshold_bytes": 1073741824,
    "volume_threshold_paths": 100,
    "volume_threshold_refusals": 50,
    "volume_threshold_burns": 10,
    "volume_window_s": 604800,
    "refusal_cooldown_s": 86400,
    "free_conversation_allowance": 50,
    "ledger_off_case_quota": 20,
    "case_batch_size": 10,
    "case_batch_timer_s": 300,
    "clock_skew_bound_s": 300,
    "clock_skew_tolerance_s": 300,
    "clock_hold_alert_after_s": 900,
    "spool_posture_window_s": 86400,
    "inbound_byte_budget_day": 52428800,
    "log_byte_budget": 1073741824,
    "quarantine_byte_budget": 524288000,
    "quarantine_per_counterpart_cap_bytes": 104857600,
    "log_archive_byte_budget": 1073741824,
    "cold_store_byte_budget": 2147483648,
    "receipt_store_budget_bytes": 268435456,
    "receipt_discharge_bound_s": 86400,
    "artifact_store_budget_bytes": 268435456,
    "severed_registry_budget_bytes": 16777216,
    "spool_bound_events": 10000,
    "incident_cap": 1,
    "max_concurrent_incidents": 3,
    "incident_reprompt_s": 604800,
    "incident_escalation_s": 1209600,
    "stall_pattern_threshold": 5,
    "component_halt_recovery_beats": 3,
    "component_halt_escalation_s": 3600,
    "component_halt_escalation_duty_deadline_s": 1209600,
    "component_halt_application_window_s": 86400,
    "component_halt_application_bound": 3,
    "duty_backfill_spacing_s": 60,
    "backfill_pending_deadline_s": 86400,
    "duty_backfill_span_max_s": 86400,
    "challenge_grace_s": 900,
    "succession_confirmation_deadline_s": 259200,
    "succession_terminal_bound_s": 1209600,
    "successor_replant_deadline_s": 86400,
    "human_key_repin_deadline_s": 2592000,
    "ceremony_sitting_cap": 3,
    "question_rounds_billed_cap": 3,
    "transfer_ready_ack_timeout_s": 300,
    "delivered_counterpart_caps": {
        "rate_cap_divisor": 2,
        "staging_priority": "lowest",
        "absolute_trust_barred": True,
    },
    "weekly_duty_cap": 10,
    "tightening_duty_deadline_s": 86400,
    "weekly_reconfirmation_bound": 20,
    "deputy_freeze_window_s": 86400,
    "freeze_episode_cap": 2,
    "manager_review_enabled": True,
    "fast_path_enabled": True,
    "absolute_trust_enabled": False,
    "precedent_path_enabled": True,
    "responsiveness_window_s": 86400,
    "scan_override_cooling_off_s": 86400,
    "request_ttl_s": 3600,
    "alert_collapse_window_s": 3600,
    "logging_enabled": True,
    "scanner_enabled": True,
    "ledger_on": False,
}

_SHARED = {
    "away_window_max_s": 2592000,
    "away_tolling_cumulative_cap_s": 15552000,
}

_STRICTER_MIN = {
    "size_cap_bytes": 10485760,
    "message_size_cap_bytes": 65536,
    "request_rate_cap_per_hour": 20,
    "absolute_trust_daily_byte_cap": 10485760,
    "massive_burst_threshold": 10,
    "big_file_threshold_bytes": 1048576,
    "signing_velocity_per_hour": 30,
    "checkpoint_interval_entries": 100,
    "checkpoint_interval_s": 900,
    "absolute_trust_expiry_days": 30,
    "challenge_timeout_s": 3600,
}

_STRICTER_MAX = {
    "absolute_trust_cooling_off_s": 86400,
    "rotation_window_days": 7,
    "appeal_filing_window_days": 7,
    "appeal_adjudication_deadline_days": 7,
    "absence_period_days": 14,
}

_INTERSECTION = {
    "file_type_allowlist": [".md", ".txt", ".png", ".jpg", ".jpeg",
                            ".gif", ".pdf", ".json", ".csv"],
}

_UNION = {
    "sensitive_type_list": [],
}

_ENUMS = {
    "kill_switch_sensitivity": (("standard", "heightened", "strict"),
                                "standard"),
    "incident_classification_strictness": (("standard", "strict"),
                                           "standard"),
}

_ATTESTATION_DEFAULT = {
    "require_design_revision": True,
    "require_manifest_version": True,
    "require_manifest_hash": True,
    "require_code_version": True,
    "require_source_hash": True,
}

_ALLOCATION_KEYS = frozenset({
    "ledger_unit", "case_price", "agent_scan_price",
    "security_team_price", "question_round_price",
    "excess_message_price", "stake", "daily_refill",
    "new_pair_balance", "new_pair_ceiling", "junk_classes",
    "duty_prices", "debt_floor", "challenge_price", "canary_price",
})

_DECLARATION_KEYS = frozenset({
    "format_versions", "design_revision", "allocation_hash",
})

_RECORD_FIELDS = frozenset({"attestation_expectations",
                            "delivered_counterpart_caps"})
_SET_FIELDS = frozenset({"file_type_allowlist", "sensitive_type_list"})

_CLASSES = {}
for _name in _PER_SIDE:
    _CLASSES[_name] = "per-side"
for _name in _SHARED:
    _CLASSES[_name] = "shared"
for _name in _STRICTER_MIN:
    _CLASSES[_name] = "min"
for _name in _STRICTER_MAX:
    _CLASSES[_name] = "max"
for _name in _INTERSECTION:
    _CLASSES[_name] = "intersection"
for _name in _UNION:
    _CLASSES[_name] = "union"
for _name in _ENUMS:
    _CLASSES[_name] = "enum"
_CLASSES["attestation_expectations"] = "attestation"

_DEFAULTS = {}
for _table in (_PER_SIDE, _SHARED, _STRICTER_MIN, _STRICTER_MAX,
               _INTERSECTION, _UNION):
    _DEFAULTS.update(_table)
for _name, (_order, _default) in _ENUMS.items():
    _DEFAULTS[_name] = _default
_DEFAULTS["attestation_expectations"] = _ATTESTATION_DEFAULT

_GOVERNING = frozenset(
    name for name, cls in _CLASSES.items() if cls != "per-side")


def _validate_values(values):
    if not isinstance(values, dict):
        raise ManifestError("manifest values must be a mapping, got %r"
                            % (values,))
    for name, value in values.items():
        if name in _ALLOCATION_KEYS:
            raise ManifestError(
                "%r is an allocation field, not a manifest field; it "
                "lives in the pair's cost-allocation artifact" % (name,))
        if name in _DECLARATION_KEYS:
            raise ManifestError(
                "%r is carried as a declaration field, not as a "
                "manifest value" % (name,))
        if name not in _CLASSES:
            raise ManifestError("unknown manifest field: %r" % (name,))
        if name in _ENUMS and value not in _ENUMS[name][0]:
            raise ManifestError(
                "%r must be one of %s, got %r"
                % (name, "/".join(_ENUMS[name][0]), value))
        if name == "attestation_expectations":
            if not isinstance(value, dict):
                raise ManifestError(
                    "attestation_expectations must be a record, got %r"
                    % (value,))
            for sub in value:
                if sub not in _ATTESTATION_DEFAULT:
                    raise ManifestError(
                        "unknown attestation_expectations field: %r"
                        % (sub,))


def _check_level(level):
    if isinstance(level, bool) or not isinstance(level, int):
        raise ManifestError("level must be an integer, got %r"
                            % (level,))
    if not 0 <= level <= 11:
        raise ManifestError("level %d outside 0..11" % (level,))


def _effective(values):
    effective = copy.deepcopy(_DEFAULTS)
    for name, value in values.items():
        if name in _RECORD_FIELDS:
            merged = copy.deepcopy(_DEFAULTS[name])
            merged.update(copy.deepcopy(value))
            effective[name] = merged
        else:
            effective[name] = copy.deepcopy(value)
    return effective


def _same(name, a, b):
    if name in _SET_FIELDS:
        return set(a) == set(b)
    return a == b


def _differs_from_default(name, value):
    return not _same(name, value, _DEFAULTS[name])


def _resolve_governing(name, local_value, remote_value):
    cls = _CLASSES[name]
    if cls == "shared":
        return copy.deepcopy(local_value)
    if cls == "min":
        return min(local_value, remote_value)
    if cls == "max":
        return max(local_value, remote_value)
    if cls == "intersection":
        remote_set = set(remote_value)
        return [item for item in local_value if item in remote_set]
    if cls == "union":
        merged = list(local_value)
        for item in remote_value:
            if item not in merged:
                merged.append(item)
        return merged
    if cls == "enum":
        order = _ENUMS[name][0]
        if order.index(local_value) >= order.index(remote_value):
            return local_value
        return remote_value
    if cls == "attestation":
        return {sub: bool(local_value[sub] or remote_value[sub])
                for sub in _ATTESTATION_DEFAULT}
    raise ManifestError("field %r has no governing rule" % (name,))


@dataclasses.dataclass
class SideDeclaration:
    side: str
    format_version: int
    design_revision: str
    level: int
    values: dict = dataclasses.field(default_factory=dict)
    allocation_hash: object = None
    cost_ledger_on: bool = False
    cost_catalogue: dict = dataclasses.field(default_factory=dict)
    absolute_trust_active: bool = False

    def __post_init__(self):
        if isinstance(self.format_version, bool) \
                or not isinstance(self.format_version, int):
            raise ManifestError(
                "format_version must be an integer, got %r"
                % (self.format_version,))
        if self.format_version < 1:
            raise ManifestError(
                "format_version must be positive, got %d"
                % (self.format_version,))
        _check_level(self.level)
        _validate_values(self.values)
        self.values = copy.deepcopy(self.values)
        self.cost_catalogue = copy.deepcopy(self.cost_catalogue)


@dataclasses.dataclass
class ConnectionManifest:
    format_version: int
    design_revision: str
    shared_level: int
    local_level: int
    remote_level: int
    governing_values: dict
    local_values: dict
    remote_values: dict
    overrides: dict
    allocation_hash: object
    cost_ledger_on: bool
    cost_catalogue: dict
    absolute_trust_active: bool


def resolve_shared_level(a, b):
    _check_level(a)
    _check_level(b)
    return max(a, b)


def agree(local, remote):
    for decl in (local, remote):
        if decl.format_version not in SUPPORTED_FORMAT_VERSIONS:
            raise VersionMismatch(
                "unsupported format version: %r (supported: %s)"
                % (decl.format_version,
                   ", ".join(str(v) for v in SUPPORTED_FORMAT_VERSIONS)))
    if local.format_version != remote.format_version:
        raise VersionMismatch(
            "format version mismatch: %r vs %r"
            % (local.format_version, remote.format_version))
    if local.design_revision != remote.design_revision \
            or local.design_revision != DESIGN_REVISION:
        raise VersionMismatch(
            "design revision mismatch: %r vs %r (this build: %r)"
            % (local.design_revision, remote.design_revision,
               DESIGN_REVISION))
    local_values = _effective(local.values)
    remote_values = _effective(remote.values)
    for name in _SHARED:
        if not _same(name, local_values[name], remote_values[name]):
            raise HandshakeRefused(
                "shared field %r does not agree: %r vs %r"
                % (name, local_values[name], remote_values[name]))
    if local.cost_ledger_on != remote.cost_ledger_on:
        raise HandshakeRefused(
            "cost ledger toggle does not agree: %r vs %r"
            % (local.cost_ledger_on, remote.cost_ledger_on))
    if local.cost_ledger_on:
        if local.cost_catalogue != remote.cost_catalogue:
            raise HandshakeRefused(
                "cost catalogue does not agree: %r vs %r"
                % (local.cost_catalogue, remote.cost_catalogue))
        if local.allocation_hash != remote.allocation_hash:
            raise HandshakeRefused(
                "allocation hash does not agree: %r vs %r"
                % (local.allocation_hash, remote.allocation_hash))
        allocation_hash = local.allocation_hash
        cost_catalogue = copy.deepcopy(local.cost_catalogue)
    else:
        allocation_hash = local.allocation_hash
        cost_catalogue = {}
    governing_values = {}
    for name in sorted(_GOVERNING):
        governing_values[name] = _resolve_governing(
            name, local_values[name], remote_values[name])
    overrides = {}
    for name in sorted(_DEFAULTS):
        if name in _GOVERNING:
            if _differs_from_default(name, governing_values[name]):
                overrides[name] = copy.deepcopy(governing_values[name])
            continue
        local_set = _differs_from_default(name, local_values[name])
        remote_set = _differs_from_default(name, remote_values[name])
        if local_set:
            overrides[name] = copy.deepcopy(local_values[name])
        elif remote_set:
            overrides[name] = copy.deepcopy(remote_values[name])
    return ConnectionManifest(
        format_version=local.format_version,
        design_revision=local.design_revision,
        shared_level=resolve_shared_level(local.level, remote.level),
        local_level=local.level,
        remote_level=remote.level,
        governing_values=governing_values,
        local_values=local_values,
        remote_values=remote_values,
        overrides=overrides,
        allocation_hash=allocation_hash,
        cost_ledger_on=local.cost_ledger_on,
        cost_catalogue=cost_catalogue,
        absolute_trust_active=bool(local.absolute_trust_active
                                   and remote.absolute_trust_active),
    )


def build_manifest_object(overrides=None, *, manifest_version=1,
                          code_version=""):
    if overrides:
        _validate_values(overrides)
    obj = _effective(overrides or {})
    obj["manifest_version"] = manifest_version
    obj["design_revision"] = DESIGN_REVISION
    obj["code_version"] = code_version
    return obj
