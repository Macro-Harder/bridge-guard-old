import hashlib
import hmac
import json
import os
import secrets
import threading
from pathlib import Path

_SIG_FIELD = "sig"


class TransferError(Exception):
    pass


class FolderAccessError(TransferError):
    pass


class TransferRefused(TransferError):
    def __init__(self, message="transfer refused", trigger=None):
        super().__init__(message)
        self.trigger = trigger


class TransferInProgress(TransferError):
    pass


class CheckerUnavailable(TransferError):
    pass


class CheckerFailure(TransferError):
    pass


class KillSwitchTripped(TransferError):
    pass


class ConnectionSevered(TransferError):
    pass


def _canonical(obj):
    return json.dumps(obj, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _material(key):
    if isinstance(key, str):
        return key.encode("utf-8")
    if isinstance(key, (bytes, bytearray)):
        return bytes(key)
    return key.material


def _body(artifact):
    return {name: value for name, value in artifact.items()
            if name != _SIG_FIELD}


def sign_artifact(artifact, key):
    signed = dict(artifact)
    signed[_SIG_FIELD] = hmac.new(
        _material(key), _canonical(_body(signed)),
        hashlib.sha256).hexdigest()
    return signed


def verify_artifact(artifact, key):
    if not isinstance(artifact, dict):
        return False
    signature = artifact.get(_SIG_FIELD)
    if not isinstance(signature, str):
        return False
    expected = hmac.new(_material(key), _canonical(_body(artifact)),
                        hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def artifact_hash(artifact):
    return hashlib.sha256(_canonical(_body(artifact))).hexdigest()


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _spoiler_match(checker, data):
    if checker is None:
        raise CheckerUnavailable("no spoiler checker is configured")
    try:
        return bool(checker.matches(data))
    except TransferError:
        raise
    except Exception as exc:
        raise CheckerFailure("spoiler checker failed: %s"
                             % (exc,)) from exc


class SpoilerChecker:
    def __init__(self, hashes):
        self.hashes = hashes

    def matches(self, data):
        return _sha256(data) in self.hashes


class KillSwitch:
    def __init__(self):
        self.tripped = False
        self.reason = None

    def trip(self, reason="spoiler"):
        self.tripped = True
        self.reason = reason

    def reset(self, signed_by=None):
        if signed_by != "human":
            raise TransferError(
                "the kill switch resets only on a human signature")
        self.tripped = False
        self.reason = None


def _write_copy(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
    return path


class Folders:
    def __init__(self, root, spoiler_checker=None, kill_switch=None):
        self.root = Path(root)
        self.staging_dir = self.root / "folder-1"
        self.outbox_dir = self.root / "folder-2"
        self.quarantine_dir = self.root / "quarantine"
        for directory in (self.root, self.staging_dir,
                          self.outbox_dir, self.quarantine_dir):
            directory.mkdir(parents=True, exist_ok=True)
            os.chmod(directory, 0o700)
        self.spoiler_checker = spoiler_checker
        self.kill_switch = kill_switch if kill_switch is not None \
            else KillSwitch()

    def staging_path(self, transfer_id):
        return self.staging_dir / transfer_id

    def outbox_path(self, transfer_id):
        return self.outbox_dir / transfer_id

    def quarantine_path(self, transfer_id):
        return self.quarantine_dir / transfer_id

    def in_staging(self, transfer_id):
        return self.staging_path(transfer_id).exists()

    def in_outbox(self, transfer_id):
        return self.outbox_path(transfer_id).exists()

    def in_quarantine(self, transfer_id):
        return self.quarantine_path(transfer_id).exists()

    def read_staged(self, transfer_id):
        return self.staging_path(transfer_id).read_bytes()

    def stage(self, role, transfer_id, data):
        if role != "manager":
            raise FolderAccessError(
                "only the manager stages into folder 1")
        if _spoiler_match(self.spoiler_checker, data):
            path = _write_copy(self.quarantine_path(transfer_id),
                               data)
            self.kill_switch.trip("spoiler")
            return path
        return _write_copy(self.staging_path(transfer_id), data)

    def write_outbox(self, role, transfer_id, data):
        if role != "transfer-agent":
            raise FolderAccessError(
                "only the transfer agent writes folder 2")
        return _write_copy(self.outbox_path(transfer_id), data)

    def move_staged_to_outbox(self, role, transfer_id):
        if role != "transfer-agent":
            raise FolderAccessError(
                "only the transfer agent moves into folder 2")
        target = self.outbox_path(transfer_id)
        os.replace(self.staging_path(transfer_id), target)
        return target

    def move_staged_to_quarantine(self, role, transfer_id):
        if role != "transfer-agent":
            raise FolderAccessError(
                "only the transfer agent drops into quarantine")
        target = self.quarantine_path(transfer_id)
        os.replace(self.staging_path(transfer_id), target)
        return target


class TransferAgent:
    def __init__(self, folders, *, agent_key, manager_key,
                 verifier_key, log, default_list=None, alerts=None,
                 absolute_trust=False, agreement=None):
        self._folders = folders
        self._agent_key = agent_key
        self._manager_key = manager_key
        self._verifier_key = verifier_key
        self._log = log
        self._default_list = default_list
        self._alerts = alerts
        self._absolute_trust = absolute_trust
        self._agreement = agreement
        self._lock = threading.Lock()
        self._in_flight = set()
        self._moved = set()
        self._spent_pass_ids = set()
        self._trust_bytes = 0

    def move(self, transfer_ready, approval_artifact, gate_pass):
        transfer_id = None
        if isinstance(transfer_ready, dict):
            transfer_id = transfer_ready.get("transfer_id")
        if transfer_id is not None:
            with self._lock:
                if transfer_id in self._in_flight:
                    raise TransferInProgress(
                        "transfer %s is already moving"
                        % (transfer_id,))
                self._in_flight.add(transfer_id)
        try:
            return self._move(transfer_ready, approval_artifact,
                              gate_pass)
        finally:
            if transfer_id is not None:
                with self._lock:
                    self._in_flight.discard(transfer_id)

    def _move(self, ready, artifact, gate_pass):
        if not isinstance(ready, dict) \
                or not verify_artifact(ready, self._manager_key):
            return None
        transfer_id = ready.get("transfer_id")
        if transfer_id in self._moved:
            return None
        if self._folders.kill_switch.tripped:
            raise ConnectionSevered(
                "the kill switch is tripped; the connection is "
                "severed until a human resets it")
        if artifact is None:
            raise TransferRefused(
                "no approval artifact accompanies transfer %s"
                % (transfer_id,))
        if artifact_hash(artifact) \
                != ready.get("approval_artifact_hash"):
            return None
        if not verify_artifact(artifact, self._manager_key):
            raise TransferRefused(
                "the approval artifact does not verify")
        if artifact.get("transfer_id") != transfer_id:
            raise TransferRefused(
                "the approval artifact names another transfer")
        try:
            data = self._folders.read_staged(transfer_id)
        except OSError:
            raise TransferRefused(
                "no staged copy exists for transfer %s"
                % (transfer_id,)) from None
        file_hash = _sha256(data)
        if ready.get("staged_hash") != file_hash:
            raise TransferRefused(
                "the staged copy does not match transfer ready")
        if artifact.get("file_hash") != file_hash:
            raise TransferRefused(
                "the staged copy does not match the approval "
                "artifact")
        if artifact.get("decision") != "approve":
            raise TransferRefused(
                "the approval artifact is not an approval")
        basis = artifact.get("basis")
        if basis == "list":
            self._check_list(artifact, transfer_id, file_hash)
        elif basis == "agreement":
            self._check_agreement(artifact, transfer_id, len(data))
        elif basis != "case":
            raise TransferRefused(
                "no move path exists for basis %r" % (basis,))
        if transfer_id not in self._log:
            self._alert_and_quarantine(transfer_id, file_hash,
                                       "not_in_logs")
        self._check_gate_pass(gate_pass, transfer_id, file_hash)
        if _spoiler_match(self._folders.spoiler_checker, data):
            self._folders.kill_switch.trip("spoiler")
            self._folders.move_staged_to_quarantine(
                "transfer-agent", transfer_id)
            raise KillSwitchTripped(
                "spoiler match on transfer %s; the connection is "
                "severed" % (transfer_id,))
        self._folders.move_staged_to_outbox("transfer-agent",
                                            transfer_id)
        self._spent_pass_ids.add(gate_pass.get("pass_id"))
        self._moved.add(transfer_id)
        if basis == "agreement":
            self._trust_bytes += len(data)
        return {"transfer_id": transfer_id, "file_hash": file_hash,
                "size": len(data)}

    def _check_list(self, artifact, transfer_id, file_hash):
        default_list = self._default_list
        if default_list is None:
            self._alert_and_quarantine(transfer_id, file_hash,
                                       "not_on_lists")
        if artifact.get("list_version") != default_list.get("version"):
            raise TransferRefused(
                "the approval artifact cites a stale list version")
        entry_hash = None
        for entry in default_list.get("entries", []):
            if entry.get("path") == artifact.get("list_entry"):
                entry_hash = entry.get("sha256")
                if entry_hash == file_hash:
                    return
        self._alert_and_quarantine(
            transfer_id,
            entry_hash if entry_hash is not None else file_hash,
            "not_on_lists")

    def _check_agreement(self, artifact, transfer_id, size):
        agreement = self._agreement
        if not self._absolute_trust or agreement is None \
                or artifact.get("agreement_id") \
                != agreement.get("agreement_id"):
            raise TransferRefused(
                "no absolute-trust agreement covers transfer %s"
                % (transfer_id,))
        cap = agreement.get("daily_byte_cap")
        if cap is not None and self._trust_bytes + size > cap:
            raise TransferRefused(
                "the agreement's daily byte cap is exhausted")

    def _check_gate_pass(self, gate_pass, transfer_id, file_hash):
        if gate_pass is None:
            raise TransferRefused("no gate-pass accompanies the "
                                  "move")
        if not verify_artifact(gate_pass, self._verifier_key):
            raise TransferRefused("the gate-pass does not verify")
        if gate_pass.get("transfer_id") != transfer_id \
                or gate_pass.get("staged_hash") != file_hash:
            raise TransferRefused(
                "the gate-pass is bound to another transfer or "
                "file")
        if gate_pass.get("pass_id") in self._spent_pass_ids:
            raise TransferRefused("the gate-pass is already spent")

    def _alert_and_quarantine(self, transfer_id, file_hash, trigger):
        record = sign_artifact({
            "record_id": "alert-" + secrets.token_hex(8),
            "transfer_id": transfer_id,
            "file_hash": file_hash,
            "trigger": trigger,
            "chain_position": len(self._log),
        }, self._agent_key)
        if self._alerts is not None:
            self._alerts.append({"to": ["manager", "boss"],
                                 "record": record})
        self._folders.move_staged_to_quarantine("transfer-agent",
                                                transfer_id)
        raise TransferRefused(
            "transfer %s refused: %s" % (transfer_id, trigger),
            trigger=trigger)
