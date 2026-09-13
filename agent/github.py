import hashlib        # 导入哈希算法库，用于生成签名
import hmac           # 导入 HMAC 模块，用于安全的消息认证码计算
import json           # 导入 JSON 库，用于处理 API 请求和响应的数据序列化/反序列化
import urllib.error   # 导入 URL 错误处理模块，用于捕获 HTTP 错误
import urllib.request # 导入 URL 请求模块，用于发送 HTTP 请求
import urllib.parse   # 导入 URL 解析模块，用于处理 URL 编码和解码
import base64         # 导入 Base64 模块，用于 GitHub 文件内容的编解码
import random         # 导入随机数模块，用于在重试时添加随机抖动（Jitter）
import threading      # 导入多线程模块，用于实现线程安全的缓存锁
import time           # 导入时间模块，用于延时、获取时间戳等
from datetime import datetime, timezone # 导入日期时间模块，用于解析 GitHub 返回的 ISO 格式时间
from typing import Dict                 # 导入类型提示工具，用于声明字典类型

def verify_signature(secret: str, body: bytes, signature: str) -> bool:
    if not secret or not signature.startswith("sha256="):
        return False
    # 使用 HMAC-SHA256 算法，结合密钥和请求体，计算出期望的哈希值，并拼接 "sha256=" 前缀
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    # 使用 hmac.compare_digest 进行安全的字符串比较，防止时序攻击（Timing Attack）
    return hmac.compare_digest(expected, signature)

class GitHubClient:
    def __init__(self, token: str, timeout: int = 30, max_attempts: int = 4):
        self.token = token
        self.timeout = timeout
        self.max_attempts = max_attempts

    def _headers(self, accept: str = "application/vnd.github+json") -> Dict[str, str]:
        # 构建基础的 HTTP 请求头，包含 Accept 类型、User-Agent 和 GitHub API 版本
        headers = {"Accept": accept, "User-Agent": "EvoAgent/0.1", "X-GitHub-Api-Version": "2022-11-28"}
        # 如果提供了 Token，则在请求头中添加 Bearer 认证信息
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        # 返回完整的请求头字典
        return headers

    def fetch_diff(self, url: str) -> str:
        # 发起 GET 请求，指定 Accept 头为 diff 格式，并设置 raw=True 获取原始字节
        body = self._request(
            "GET", url, accept="application/vnd.github.v3.diff", raw=True
        )
        # 将字节流解码为 UTF-8 字符串，遇到无法解码的字符则替换，防止报错
        return body.decode("utf-8", errors="replace")

    def post_comment(self, api_url: str, markdown: str) -> None:
        # 拼接评论接口的 URL
        url = api_url.rstrip("/") + "/comments"
        # 构建 POST 请求，将 Markdown 内容序列化为 JSON 并编码为字节
        request = urllib.request.Request(
            url,
            data=json.dumps({"body": markdown}).encode("utf-8"),
            headers=dict(self._headers(), **{"Content-Type": "application/json"}),
            method="POST",
        )
        # 发送请求并自动关闭响应流，不返回任何内容
        with urllib.request.urlopen(request, timeout=self.timeout):
            return None

    def upsert_comment(self, api_url: str, markdown: str, marker: str) -> None:
        """Update this service's existing review comment instead of creating duplicates."""
        # 拼接评论列表接口
        comments_url = api_url.rstrip("/") + "/comments"
        # 获取前 100 条评论
        comments = self._json("GET", comments_url + "?per_page=100")
        # 将标记（marker）和 Markdown 内容拼接成新的评论体
        body = marker + "\n" + markdown
        # 遍历现有评论
        for comment in comments:
            # 如果某条评论的 body 中包含指定的 marker
            if marker in str(comment.get("body", "")):
                # 使用 PATCH 方法更新该评论，然后直接返回，避免重复创建
                self._json("PATCH", comment["url"], {"body": body})
                return
        # 如果没有找到包含 marker 的评论，则使用 POST 方法创建一条新评论
        self._json("POST", comments_url, {"body": body})

    def _json(self, method: str, url: str, payload=None):
        # 调用底层的 _request 方法处理 JSON 数据
        return self._request(method, url, payload)

    def _request(
        self, method: str, url: str, payload=None,
        accept: str = "application/vnd.github+json", raw: bool = False,
    ):
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        for attempt in range(1, self.max_attempts + 1):
            request = urllib.request.Request(
                url, data=data,
                headers=dict(self._headers(accept), **{"Content-Type": "application/json"}),
                method=method,
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    body = response.read()
                    if raw:
                        return body
                    return json.loads(body.decode("utf-8")) if body else {}
            except urllib.error.HTTPError as exc:
                retryable = exc.code in {429, 500, 502, 503, 504}
                if exc.code == 403 and exc.headers.get("X-RateLimit-Remaining") == "0":
                    retryable = True
                if not retryable or attempt >= self.max_attempts:
                    detail = exc.read(1000).decode("utf-8", errors="replace")
                    raise RuntimeError(
                        "GitHub API %s %s returned HTTP %d: %s"
                        % (method, url, exc.code, detail)
                    ) from exc
                retry_after = exc.headers.get("Retry-After")
                reset = exc.headers.get("X-RateLimit-Reset")
                if retry_after:
                    delay = float(retry_after)
                elif reset:
                    delay = max(0.0, float(reset) - time.time())
                else:
                    delay = min(2 ** (attempt - 1) + random.random(), 10)
                time.sleep(min(delay, 30))
            except (urllib.error.URLError, TimeoutError) as exc:
                if attempt >= self.max_attempts:
                    raise RuntimeError("GitHub API request failed: %s" % exc) from exc
                time.sleep(min(2 ** (attempt - 1) + random.random(), 10))

    def get_pull_request(self, repository: str, number: int) -> dict:
        return self._json("GET", "https://api.github.com/repos/%s/pulls/%d" % (repository, number))

    def get_file(self, repository: str, path: str, ref: str) -> dict:
        quoted = urllib.parse.quote(path, safe="/")
        result = self._json("GET", "https://api.github.com/repos/%s/contents/%s?ref=%s" % (
            repository, quoted, urllib.parse.quote(ref, safe="")
        ))
        result["decoded_content"] = base64.b64decode(result["content"]).decode("utf-8")
        return result

    def get_repository(self, repository: str) -> dict:
        return self._json("GET", "https://api.github.com/repos/%s" % repository)

    def ensure_repository_access(self, repository: str) -> None:
        result = self.get_repository(repository)
        if str(result.get("full_name", "")).lower() != repository.lower():
            raise PermissionError("GitHub installation is not authorized for this repository")

    def create_branch(self, repository: str, branch: str, sha: str) -> None:
        self._json("POST", "https://api.github.com/repos/%s/git/refs" % repository,
                   {"ref": "refs/heads/" + branch, "sha": sha})

    def commit_file(self, repository: str, path: str, branch: str, content: str, sha: str, message: str) -> dict:
        quoted = urllib.parse.quote(path, safe="/")
        return self._json("PUT", "https://api.github.com/repos/%s/contents/%s" % (repository, quoted), {
            "message": message, "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
            "sha": sha, "branch": branch,
        })

    def create_atomic_commit(
        self, repository: str, branch: str, parent_sha: str,
        files: Dict[str, str], message: str,
    ) -> dict:
        parent = self._json(
            "GET", "https://api.github.com/repos/%s/git/commits/%s"
            % (repository, parent_sha)
        )
        tree = self._json(
            "POST", "https://api.github.com/repos/%s/git/trees" % repository,
            {
                "base_tree": parent["tree"]["sha"],
                "tree": [
                    {"path": path, "mode": "100644", "type": "blob", "content": content}
                    for path, content in sorted(files.items())
                ],
            },
        )
        commit = self._json(
            "POST", "https://api.github.com/repos/%s/git/commits" % repository,
            {"message": message, "tree": tree["sha"], "parents": [parent_sha]},
        )
        self.create_branch(repository, branch, commit["sha"])
        return commit

    def create_draft_pull_request(
        self, repository: str, title: str, head: str, base: str, body: str,
    ) -> dict:
        return self._json(
            "POST", "https://api.github.com/repos/%s/pulls" % repository,
            {"title": title, "head": head, "base": base, "body": body, "draft": True},
        )

    def download_archive(self, repository: str, ref: str) -> bytes:
        return self._request(
            "GET", "https://api.github.com/repos/%s/zipball/%s"
            % (repository, urllib.parse.quote(ref, safe="")),
            accept="application/vnd.github+json", raw=True,
        )


class GitHubAppAuthenticator:
    _cache = {}
    _lock = threading.Lock()
    def __init__(self, app_id: str, private_key_path: str):
        self.app_id = app_id
        self.private_key_path = private_key_path

    def app_jwt(self) -> str:
        try:
            import jwt
        except ImportError as exc:
            raise RuntimeError("GitHub App mode requires: pip install PyJWT[crypto]") from exc
        with open(self.private_key_path, "rb") as handle:
            key = handle.read()
        now = int(time.time())
        return jwt.encode({"iat": now - 60, "exp": now + 540, "iss": self.app_id}, key, algorithm="RS256")

    def installation_token(self, installation_id: int) -> str:
        cache_key = (self.app_id, int(installation_id))
        with self._lock:
            cached = self._cache.get(cache_key)
            if cached and cached["expires_at"] > time.time() + 120:
                return cached["token"]
        request = urllib.request.Request(
            "https://api.github.com/app/installations/%d/access_tokens" % installation_id,
            data=b"{}", method="POST",
            headers={"Authorization": "Bearer " + self.app_jwt(), "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "EvoAgent/0.3",
                     "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            result = json.loads(response.read().decode("utf-8"))
        expires = result.get("expires_at", "")
        try:
            expires_at = datetime.fromisoformat(expires.replace("Z", "+00:00")).timestamp()
        except ValueError:
            expires_at = time.time() + 3000
        with self._lock:
            self._cache[cache_key] = {"token": result["token"], "expires_at": expires_at}
        return result["token"]