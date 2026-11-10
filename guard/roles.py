import dataclasses
import hashlib
import json
import secrets

from guard import ed25519

_SECONDS_PER_DAY = 86400

_CAPABILITIES = {
    "owner": {"task": True, "prompt": True, "message": True,
              "result": True},
    "master": {"task": True, "prompt": True, "message": True,
               "result": True},
    "worker": {"task": False, "prompt": True, "message": True,
               "result": True},
    "asker": {"task": False, "prompt": True, "message": True,
              "result": False},
    "slave": {"task": False, "prompt": False, "message": False,
              "result": True},
    "relay": {"task": False, "prompt": False, "message": False,
              "result": False},
}


@dataclasses.dataclass(frozen=True)
class KeyPair:
    secret: str
    public: str


def _canonical(obj):
    return json.dumps(obj, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _material(token):
    text = token.split("-", 1)[1] if "-" in token else token
    return bytes.fromhex(text)


def generate_keypair():
    seed = secrets.token_bytes(32)
    return KeyPair(secret="sk-" + seed.hex(),
                   public="pk-" + ed25519.publickey(seed).hex())


def sign(secret, obj):
    return ed25519.sign(_material(secret), _canonical(obj)).hex()


def _verify(public, obj, sig):
    if not isinstance(sig, str) or not sig:
        return False
    try:
        signature = bytes.fromhex(sig)
        key = _material(public)
    except (ValueError, TypeError):
        return False
    return ed25519.verify(key, _canonical(obj), signature)


def verify(public, obj, sig):
    """_verify under a public name, for the package's other gates
    (guard.formats checks relayed origin signatures with it)."""
    return _verify(public, obj, sig)


def pair_hash(first_public, second_public):
    return hashlib.sha256(
        _canonical([first_public, second_public])).hexdigest()


def may(role, action):
    table = _CAPABILITIES.get(role)
    if table is None:
        return False
    return table.get(action, False)


def make_certificate(issuer_secret, subject, role, public, epoch=0):
    body = {"subject": subject, "role": role, "public": public,
            "epoch": epoch}
    cert = dict(body)
    cert["sig"] = sign(issuer_secret, body)
    return cert


class RoleRegistry:
    def __init__(self, master_public):
        self._master_public = master_public
        self._current = {}
        self._by_public = {}
        self._intervals = {}

    def _open_interval(self, public, epoch):
        self._intervals.setdefault(public, []).append([epoch, None])

    def _close_interval(self, public, epoch):
        for interval in self._intervals.get(public, []):
            if interval[1] is None:
                interval[1] = epoch

    def _trim_intervals(self, public, epoch):
        kept = []
        for start, end in self._intervals.get(public, []):
            if start >= epoch:
                continue
            kept.append([start, epoch if end is None or end > epoch
                         else end])
        self._intervals[public] = kept

    def add_certificate(self, cert):
        if not isinstance(cert, dict):
            return False
        try:
            body = {"subject": cert["subject"], "role": cert["role"],
                    "public": cert["public"], "epoch": cert["epoch"]}
            sig = cert["sig"]
        except (KeyError, TypeError):
            return False
        if not _verify(self._master_public, body, sig):
            return False
        subject = body["subject"]
        public = body["public"]
        epoch = body["epoch"]
        current = self._current.get(subject)
        if current is not None and epoch <= current["epoch"]:
            return False
        if current is not None and current["public"] != public:
            old_public = current["public"]
            self._close_interval(old_public, epoch)
            self._by_public.pop(old_public, None)
        previous_subject = self._by_public.get(public)
        if previous_subject is not None and previous_subject != subject:
            self._current.pop(previous_subject, None)
            self._close_interval(public, epoch)
        self._close_interval(public, epoch)
        self._open_interval(public, epoch)
        self._current[subject] = {"public": public, "role": body["role"],
                                  "epoch": epoch}
        self._by_public[public] = subject
        return True

    def role_for(self, public):
        subject = self._by_public.get(public)
        if subject is None:
            return None
        current = self._current.get(subject)
        if current is None:
            return None
        return current["role"]

    def verify_envelope(self, envelope):
        if not isinstance(envelope, dict):
            return None
        signer = envelope.get("signer")
        role = self.role_for(signer)
        if role is None:
            return None
        if not _verify(signer, envelope.get("msg"), envelope.get("sig")):
            return None
        return role

    def authorize(self, envelope, action):
        role = self.verify_envelope(envelope)
        if role is None:
            return False
        return may(role, action)

    def rotate_role_key(self, subject, new_public, epoch, sig):
        current = self._current.get(subject)
        if current is None:
            return False
        if epoch != current["epoch"] + 1:
            return False
        body = {"subject": subject, "new_public": new_public,
                "epoch": epoch}
        if not _verify(current["public"], body, sig):
            return False
        old_public = current["public"]
        self._close_interval(old_public, epoch)
        self._by_public.pop(old_public, None)
        previous_subject = self._by_public.get(new_public)
        if previous_subject is not None and previous_subject != subject:
            self._current.pop(previous_subject, None)
            self._close_interval(new_public, epoch)
        self._open_interval(new_public, epoch)
        self._current[subject] = {"public": new_public,
                                  "role": current["role"], "epoch": epoch}
        self._by_public[new_public] = subject
        return True

    def revoke_key(self, public, epoch):
        known = public in self._intervals or public in self._by_public
        if not known:
            return False
        self._trim_intervals(public, epoch)
        subject = self._by_public.pop(public, None)
        if subject is not None:
            self._current.pop(subject, None)
        return True

    def verify_artifact(self, public, payload, sig, epoch):
        standing = False
        for start, end in self._intervals.get(public, []):
            if start <= epoch and (end is None or epoch < end):
                standing = True
                break
        if not standing:
            return False
        return _verify(public, payload, sig)


class PairKeys:
    def __init__(self, counterpart, first_public, second_public):
        self.counterpart = counterpart
        self.keys = (first_public, second_public)
        self.epoch = 0
        self.broken = False
        self.frozen = False
        self._revoked = set()

    def current_hash(self):
        return pair_hash(self.keys[0], self.keys[1])

    def is_current(self, public):
        return public in self.keys and public not in self._revoked

    def rotate(self, introduction):
        if self.broken or self.frozen:
            return "inert"
        if not isinstance(introduction, dict):
            return "inert"
        sigs = introduction.get("sigs")
        if not isinstance(sigs, list) or len(sigs) != 2:
            return "inert"
        body = {key: value for key, value in introduction.items()
                if key != "sigs"}
        for index in (0, 1):
            if not _verify(self.keys[index], body, sigs[index]):
                return "inert"
        if introduction.get("extends_epoch") != self.epoch + 1:
            return "inert"
        if introduction.get("current_key_hash") != self.current_hash():
            return "inert"
        new_keys = introduction.get("new_keys")
        if not isinstance(new_keys, list):
            return "inert"
        if len(new_keys) != 2 or len(set(new_keys)) != 2:
            self.broken = True
            return "violation"
        changed = sum(1 for index in (0, 1)
                      if new_keys[index] != self.keys[index])
        if changed == 0:
            return "inert"
        if changed == 2:
            self.broken = True
            return "violation"
        self.keys = (new_keys[0], new_keys[1])
        self.epoch = introduction["extends_epoch"]
        return "applied"

    def revoke(self, public):
        if public not in self.keys or public in self._revoked:
            return False
        self._revoked.add(public)
        self.frozen = True
        return True


def make_agreement(agreement_id, pair_fingerprint, roots,
                   daily_byte_cap, expiry, proposer_secret):
    body = {"agreement_id": agreement_id,
            "pair_fingerprint": pair_fingerprint,
            "roots": list(roots),
            "daily_byte_cap": daily_byte_cap,
            "expiry": expiry}
    agreement = dict(body)
    agreement["signatures"] = [sign(proposer_secret, body)]
    return agreement


def countersign_agreement(agreement, countersigner_secret):
    body = {key: value for key, value in agreement.items()
            if key != "signatures"}
    agreement["signatures"] = list(agreement.get("signatures", []))
    agreement["signatures"].append(sign(countersigner_secret, body))
    return agreement


class TrustBook:
    def __init__(self, pair, local_human_public, remote_human_public,
                 cooling_off_s=86400):
        self.pair = pair
        self.local_human_public = local_human_public
        self.remote_human_public = remote_human_public
        self.cooling_off_s = cooling_off_s
        self.events = []
        self._agreement = None
        self._activated_at = None
        self._turned_off = False
        self._cap_tripped = False
        self._day = None
        self._day_total = 0

    def activate(self, agreement, now):
        if not isinstance(agreement, dict):
            return False
        signatures = agreement.get("signatures")
        if not isinstance(signatures, list):
            return False
        body = {key: value for key, value in agreement.items()
                if key != "signatures"}
        matched = set()
        for public in (self.local_human_public,
                       self.remote_human_public):
            for sig in signatures:
                if _verify(public, body, sig):
                    matched.add(public)
                    break
        if matched != {self.local_human_public,
                       self.remote_human_public}:
            return False
        self._agreement = agreement
        self._activated_at = now
        self._turned_off = False
        self._cap_tripped = False
        self._day = None
        self._day_total = 0
        self.events.append({
            "type": "trust-on",
            "counterpart": self.pair.counterpart,
            "by": self.local_human_public,
            "agreement_id": agreement.get("agreement_id"),
            "ts": now,
        })
        return True

    def is_active(self, now):
        if self._agreement is None or self._turned_off:
            return False
        if self._cap_tripped:
            return False
        if self.pair.broken or self.pair.frozen:
            return False
        if now < self._activated_at + self.cooling_off_s:
            return False
        if now >= self._activated_at + self._agreement["expiry"]:
            return False
        return True

    def record_send(self, nbytes, now):
        if not self.is_active(now):
            return False
        day = now // _SECONDS_PER_DAY
        if day != self._day:
            self._day = day
            self._day_total = 0
        if self._day_total + nbytes > self._agreement["daily_byte_cap"]:
            self._cap_tripped = True
            return False
        self._day_total += nbytes
        return True

    def reconfirm(self, now):
        self._cap_tripped = False

    def turn_off(self, now):
        if self._agreement is None or self._turned_off:
            return
        self._turned_off = True
        self.events.append({
            "type": "trust-off",
            "counterpart": self.pair.counterpart,
            "by": self.local_human_public,
            "agreement_id": self._agreement.get("agreement_id"),
            "ts": now,
        })
