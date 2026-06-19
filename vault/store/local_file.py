from __future__ import annotations
import json
import os
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from vault.crypto import KeyWrapper, seal_token, open_token
from vault.model import Connection, ConnKey, ConnectionGrant, ConnectionAccessLog, Token
from vault.store.base import Store


class LocalFileStore(Store):
    def __init__(self, root: Path, wrapper: KeyWrapper):
        self.root = Path(root)
        self.wrapper = wrapper

    def _dir(self, key: ConnKey) -> Path:
        return self.root / "connections" / key.org / key.provider

    def _rec_path(self, key: ConnKey) -> Path:
        return self._dir(key) / f"{key.account}.json"

    def _tok_path(self, key: ConnKey) -> Path:
        return self._dir(key) / f"{key.account}.token.age"

    def _lock_path(self, key: ConnKey) -> Path:
        return self._dir(key) / f"{key.account}.lock"

    def _write_sealed(self, key: ConnKey, token: Token) -> None:
        p = self._tok_path(key)
        # Unique temp per writer so concurrent sealers never collide on one path.
        fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=f"{key.account}.token.", suffix=".tmp")
        try:
            os.write(fd, seal_token(token, self.wrapper))
        finally:
            os.close(fd)
        os.replace(tmp, str(p))  # atomic on POSIX; readers never see a truncated file

    def put_connection(self, conn: Connection) -> None:
        self._dir(conn.key).mkdir(parents=True, exist_ok=True)
        self._rec_path(conn.key).write_text(json.dumps(conn.to_record()))
        if conn.token is not None:
            self._write_sealed(conn.key, conn.token)

    def get_connection(self, key: ConnKey) -> Optional[Connection]:
        rp = self._rec_path(key)
        if not rp.exists():
            return None
        rec = json.loads(rp.read_text())
        token = None
        if self._tok_path(key).exists():
            token = open_token(self._tok_path(key).read_bytes(), self.wrapper)
        return Connection.from_record(rec, token=token)

    def list_connections(self, org: str, provider: Optional[str]) -> list[Connection]:
        base = self.root / "connections" / org
        out = []
        if not base.exists():
            return out
        for prov_dir in base.iterdir():
            if provider is not None and prov_dir.name != provider:
                continue
            for rec in prov_dir.glob("*.json"):
                acct = rec.stem
                out.append(self.get_connection(ConnKey(org, prov_dir.name, acct)))
        return out

    def write_token(self, key: ConnKey, token: Token, now: float) -> None:
        self._write_sealed(key, token)
        rp = self._rec_path(key)
        rec = json.loads(rp.read_text())
        rec["updated_at"] = now
        tmp = rp.with_suffix(".tmp")
        tmp.write_text(json.dumps(rec))
        os.replace(str(tmp), str(rp))  # atomic on POSIX

    def _lease_until(self, p: Path) -> Optional[float]:
        # None means "present but content not parseable" — treat as a live lock,
        # never as expired, so a lock seen mid-creation is never falsely stolen.
        try:
            return float(p.read_text().split("\n", 1)[1])
        except (OSError, IndexError, ValueError):
            return None

    def acquire_lease(self, key: ConnKey, holder: str, until: float, now: float) -> bool:
        self._dir(key).mkdir(parents=True, exist_ok=True)
        p = self._lock_path(key)
        # Write the full lease content to a unique temp first, then publish it
        # atomically. os.link makes existence and content appear together, so a
        # concurrent acquirer can never read an empty half-created lock and steal it.
        fd, tmp = tempfile.mkstemp(dir=str(self._dir(key)), prefix=f"{key.account}.lock.", suffix=".tmp")
        try:
            os.write(fd, f"{holder}\n{until}".encode())
            os.close(fd)
            try:
                os.link(tmp, str(p))
                return True
            except FileExistsError:
                cur_until = self._lease_until(p)
                if cur_until is None or cur_until > now:
                    return False
                # Expired: publish our content atomically (last writer wins) and
                # re-read to confirm we are the survivor — exactly one stealer wins.
                os.replace(tmp, str(p))
                tmp = None  # consumed by os.replace
                try:
                    return p.read_text().split("\n", 1)[0] == holder
                except OSError:
                    return False
        finally:
            if tmp is not None and os.path.exists(tmp):
                os.unlink(tmp)

    def release_lease(self, key: ConnKey, holder: str) -> None:
        p = self._lock_path(key)
        try:
            if p.exists() and p.read_text().split("\n", 1)[0] == holder:
                p.unlink()
        except OSError:
            pass

    def lease_held(self, key: ConnKey, now: float) -> bool:
        p = self._lock_path(key)
        if not p.exists():
            return False
        cur_until = self._lease_until(p)
        # Unparseable (mid-creation) counts as held, mirroring acquire_lease.
        return cur_until is None or cur_until > now

    def delete_connection(self, key: ConnKey) -> None:
        tok = self._tok_path(key)
        if tok.exists():
            size = tok.stat().st_size
            with open(tok, "wb") as f:
                f.write(b"\x00" * size)
                f.flush()
                os.fsync(f.fileno())
            tok.unlink()
        for p in (self._rec_path(key), self._lock_path(key)):
            if p.exists():
                p.unlink()

    def _jsonl(self, sub: str, cid: str) -> Path:
        return self.root / sub / f"{cid}.jsonl"

    def add_grant(self, grant: ConnectionGrant) -> None:
        p = self._jsonl("grants", grant.connection_id)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a") as f:
            f.write(json.dumps(asdict(grant)) + "\n")

    def get_grants(self, connection_id: str) -> list[ConnectionGrant]:
        p = self._jsonl("grants", connection_id)
        if not p.exists():
            return []
        return [ConnectionGrant(**json.loads(line)) for line in p.read_text().splitlines() if line]

    def append_log(self, entry: ConnectionAccessLog) -> None:
        p = self._jsonl("logs", entry.connection_id)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a") as f:
            f.write(json.dumps(asdict(entry)) + "\n")

    def read_log(self, connection_id: str) -> list[ConnectionAccessLog]:
        p = self._jsonl("logs", connection_id)
        if not p.exists():
            return []
        return [ConnectionAccessLog(**json.loads(line)) for line in p.read_text().splitlines() if line]
