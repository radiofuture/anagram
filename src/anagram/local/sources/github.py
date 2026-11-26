"""GitHub connector: device-flow OAuth and a commit reader.

Device flow (RFC 8628, as GitHub runs it) works for a local app with no
redirect URL:

1. `start()` posts the client ID to `https://github.com/login/device/code`.
   GitHub returns a user code and a verification URL. The UI shows them.
2. The user opens the URL and types the code.
3. `poll()` posts the device code to `https://github.com/login/oauth/access_token`
   until GitHub returns a token (or `access_denied`, `expired_token`).

The token goes into the client keystore (`github-token`). It never goes to the
community node. Private repositories are read only on the device.

Each commit of each selected repository is one evidence item (a record): the
commit SHA, tree SHA, parents, time, and message. GitHub does not give file
bytes here, so there is no SHA-256 tree hash; for that, clone the repository
and use the Git connector.

`FakeGitHub` is a deterministic transport for tests. No test uses the network.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field

from anagram.local.sources.base import (
    Connector,
    ConnectorError,
    EvidenceItem,
    KnownItem,
    SourceContext,
    Transport,
    record_item,
    urllib_transport,
    with_query,
)

DEVICE_CODE_URL = "https://github.com/login/device/code"
TOKEN_URL = "https://github.com/login/oauth/access_token"  # noqa: S105 - URL, not a secret
API = "https://api.github.com"
GRANT = "urn:ietf:params:oauth:grant-type:device_code"
COMMIT_KIND = "github_commit"


@dataclass(frozen=True)
class DeviceCode:
    device_code: str
    user_code: str
    verification_uri: str
    interval: int
    expires_in: int


class DeviceFlowError(ConnectorError):
    pass


def _form(params: Mapping[str, str]) -> bytes:
    import urllib.parse

    return urllib.parse.urlencode(params).encode()


class GitHubDeviceFlow:
    def __init__(
        self,
        client_id: str,
        scope: str = "repo read:user",
        transport: Transport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.client_id = client_id
        self.scope = scope
        self.transport = transport or urllib_transport()
        self.sleep = sleep

    def _post(self, url: str, params: Mapping[str, str]) -> dict:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        status, body = self.transport("POST", url, headers, _form(params))
        if status != 200 or not isinstance(body, dict):
            raise DeviceFlowError(f"GitHub returned status {status}")
        return body

    def start(self) -> DeviceCode:
        b = self._post(DEVICE_CODE_URL, {"client_id": self.client_id, "scope": self.scope})
        return DeviceCode(
            device_code=b["device_code"],
            user_code=b["user_code"],
            verification_uri=b["verification_uri"],
            interval=int(b.get("interval", 5)),
            expires_in=int(b.get("expires_in", 900)),
        )

    def poll(self, code: DeviceCode, max_tries: int = 200) -> str:
        interval = code.interval
        for _ in range(max_tries):
            b = self._post(
                TOKEN_URL,
                {"client_id": self.client_id, "device_code": code.device_code, "grant_type": GRANT},
            )
            if "access_token" in b:
                return b["access_token"]
            err = b.get("error")
            if err == "authorization_pending":
                self.sleep(interval)
            elif err == "slow_down":
                interval = int(b.get("interval", interval + 5))
                self.sleep(interval)
            else:
                raise DeviceFlowError(f"device flow failed: {err}")
        raise DeviceFlowError("device flow timed out")


class GitHubConnector(Connector):
    kind = "github"
    label = "GitHub"

    @classmethod
    def from_config(cls, cfg: dict, ctx: SourceContext) -> GitHubConnector:
        if ctx.secret is None:
            raise ConnectorError(f"{cls.kind} needs a token from the keystore")
        return cls(ctx.secret("github-token"), cfg["repos"], ctx.transport)

    def __init__(
        self, token: str, repos: list[str], transport: Transport | None = None, per_page: int = 100
    ) -> None:
        self._token = token
        self.repos = sorted(repos)  # "owner/name"
        self.transport = transport or urllib_transport()
        self.per_page = per_page

    def config(self) -> dict:
        # The token is not in the config. It stays in the keystore.
        return {"kind": self.kind, "repos": self.repos}

    def describe(self) -> str:
        return "github " + ", ".join(self.repos)

    def _get(self, url: str) -> object:
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        status, body = self.transport("GET", url, headers, None)
        if status != 200:
            raise ConnectorError(f"GitHub API status {status} for {url}")
        return body

    def commits(self, repo: str) -> list[dict]:
        out: list[dict] = []
        page = 1
        while True:
            url = with_query(
                f"{API}/repos/{repo}/commits", {"per_page": self.per_page, "page": page}
            )
            batch = self._get(url)
            if not isinstance(batch, list) or not batch:
                break
            out.extend(batch)
            if len(batch) < self.per_page:
                break
            page += 1
        return out

    def scan(self, known: Mapping[str, KnownItem]) -> Iterator[EvidenceItem]:
        for repo in self.repos:
            for c in self.commits(repo):
                commit = c["commit"]
                record = {
                    "commit": c["sha"],
                    "committer_time": commit["committer"]["date"],
                    "message": commit["message"],
                    "parents": [p["sha"] for p in c.get("parents", [])],
                    "repo": repo,
                    "tree": commit["tree"]["sha"],
                }
                first = commit["message"].splitlines()[0] if commit["message"] else None
                yield record_item(
                    key=f"{repo}@{c['sha']}",
                    kind=COMMIT_KIND,
                    name=first,
                    ref=f"github:{repo}@{c['sha']}",
                    record=record,
                    text=commit["message"],
                    title=first,
                    prose=True,
                    time=commit["committer"]["date"],
                )


# --------------------------------------------------------------------- fake


@dataclass
class FakeGitHub:
    """A deterministic GitHub for tests. Call it as a `Transport`.

    `approve_after` polls return `authorization_pending` before the token."""

    client_id: str = "fake-client"
    token: str = "fake-token-0001"  # noqa: S105 - test value
    approve_after: int = 1
    deny: bool = False
    repos: dict[str, list[dict]] = field(default_factory=dict)
    calls: list[tuple[str, str]] = field(default_factory=list)
    _polls: int = 0

    def add_commit(self, repo: str, sha: str, tree: str, message: str, date: str) -> None:
        parents = [{"sha": c["sha"]} for c in self.repos.get(repo, [])[:1]]
        entry = {
            "sha": sha,
            "commit": {"message": message, "tree": {"sha": tree}, "committer": {"date": date}},
            "parents": parents,
        }
        # GitHub lists the newest commit first.
        self.repos.setdefault(repo, []).insert(0, entry)

    def __call__(self, method: str, url: str, headers: dict[str, str], body: bytes | None):
        import urllib.parse

        self.calls.append((method, url))
        if url == DEVICE_CODE_URL:
            return 200, {
                "device_code": "fake-device-code",
                "user_code": "FAKE-0001",
                "verification_uri": "https://github.com/login/device",
                "interval": 5,
                "expires_in": 900,
            }
        if url == TOKEN_URL:
            return 200, self._token_answer(dict(urllib.parse.parse_qsl((body or b"").decode())))
        if headers.get("Authorization") != f"Bearer {self.token}":
            return 401, {"message": "Bad credentials"}
        return self._api(url)

    def _token_answer(self, form: dict) -> dict:
        """The answer of the token endpoint to one poll of the device flow."""
        if form.get("client_id") != self.client_id:
            return {"error": "incorrect_client_credentials"}
        if self.deny:
            return {"error": "access_denied"}
        self._polls += 1
        if self._polls <= self.approve_after:
            return {"error": "authorization_pending"}
        return {"access_token": self.token, "token_type": "bearer", "scope": "repo"}

    def _api(self, url: str) -> tuple[int, object]:
        """The answer to an authorized API request (the commit list only)."""
        import urllib.parse

        parsed = urllib.parse.urlparse(url)
        parts = parsed.path.strip("/").split("/")
        if len(parts) == 4 and parts[0] == "repos" and parts[3] == "commits":
            repo = f"{parts[1]}/{parts[2]}"
            if repo not in self.repos:
                return 404, {"message": "Not Found"}
            q = dict(urllib.parse.parse_qsl(parsed.query))
            per, page = int(q.get("per_page", 30)), int(q.get("page", 1))
            return 200, self.repos[repo][(page - 1) * per : page * per]
        return 404, {"message": "Not Found"}
