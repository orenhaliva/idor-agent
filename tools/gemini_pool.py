"""Gemini free-tier pool: rotates across every (API key x model) pair.

- Daily quota hit (429 *PerDay*)      -> that pair is parked until restart (state saved to .cache/gemini_pool.json)
- Per-minute quota (429 other)       -> wait retryDelay, retry same pair (max 2 times), then next pair
- 5xx / timeout / overloaded         -> next pair
- 404 (model gone for this key)      -> pair removed

`exclude` lets the caller force a DIFFERENT model (blank judge must not be the investigator's model).
Keys come from GEMINI_API_KEYS (comma separated) or GEMINI_API_KEY.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

# strongest first; all were verified to exist on the free tier (Pro models had 0 free quota)
DEFAULT_MODELS = [
    "gemini-3.8-flash", "gemini-3.7-flash", "gemini-3.6-flash", "gemini-3.5-flash", "gemini-3-flash-preview",
    "gemini-flash-latest", "gemini-3.5-flash-lite", "gemini-3.1-flash-lite", "gemini-flash-lite-latest", "gemma-4-31b-it",
]
STATE = Path(__file__).resolve().parent.parent / ".cache" / "gemini_pool.json"
URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


def load_env():
    env = Path(__file__).resolve().parent.parent / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


class PoolExhausted(RuntimeError):
    pass


class GeminiPool:
    def __init__(self, models: list[str] | None = None, verbose: bool = True):
        load_env()
        keys = os.environ.get("GEMINI_API_KEYS") or os.environ.get("GEMINI_API_KEY", "")
        self.keys = [k.strip() for k in keys.split(",") if k.strip()]
        if not self.keys:
            raise SystemExit("set GEMINI_API_KEYS (or GEMINI_API_KEY) in .env")
        env_models = os.environ.get("GEMINI_MODELS")
        self.models = models or ([m.strip() for m in env_models.split(",")] if env_models else DEFAULT_MODELS)
        self.verbose = verbose
        self.dead: dict[str, str] = {}
        self.calls: dict[str, int] = {}
        self._load()

    # ---- state -------------------------------------------------------------------------
    def _pair(self, ki, model):
        return f"k{ki}:{model}"

    def _load(self):
        if STATE.exists():
            s = json.loads(STATE.read_text())
            if s.get("day") == date.today().isoformat():
                self.dead = s.get("dead", {})
                self.calls = s.get("calls", {})

    def _save(self):
        STATE.parent.mkdir(parents=True, exist_ok=True)
        STATE.write_text(json.dumps({"day": date.today().isoformat(), "dead": self.dead, "calls": self.calls}, indent=1))

    def pairs(self, exclude_models=()):
        for m in self.models:
            if m in exclude_models:
                continue
            for ki in range(len(self.keys)):
                if self._pair(ki, m) not in self.dead:
                    yield ki, m

    def log(self, msg):
        if self.verbose:
            print(f"  [pool] {msg}", flush=True)

    # ---- call --------------------------------------------------------------------------
    def generate(self, body: dict, exclude_models=(), prefer_model: str | None = None, timeout=300) -> tuple[dict, str]:
        """POST generateContent. Returns (response_json, model_used)."""
        order = list(self.pairs(exclude_models))
        if prefer_model:
            order.sort(key=lambda p: p[1] != prefer_model)
        if not order:
            raise PoolExhausted("every key x model pair is exhausted for today")
        for ki, model in order:
            pair = self._pair(ki, model)
            for attempt in range(3):
                req = urllib.request.Request(URL.format(model=model), json.dumps(body).encode(),
                                             {"Content-Type": "application/json", "X-goog-api-key": self.keys[ki]})
                try:
                    with urllib.request.urlopen(req, timeout=timeout) as r:
                        data = json.loads(r.read())
                    self.calls[pair] = self.calls.get(pair, 0) + 1
                    self._save()
                    if not data.get("candidates"):
                        self.log(f"{pair} returned no candidates ({data.get('promptFeedback')}); next")
                        break
                    return data, model
                except urllib.error.HTTPError as e:
                    txt = e.read().decode(errors="replace")
                    if e.code == 429 and ("PerDay" in txt or "quotaValue\": \"0\"" in txt or "limit: 0" in txt):
                        self.dead[pair] = "daily quota"; self._save()
                        self.log(f"{pair} daily quota exhausted; next")
                        break
                    if e.code == 429 and attempt < 2:
                        m = re.search(r'"retryDelay":\s*"(\d+)', txt)
                        wait = min(int(m.group(1)) + 1 if m else 20, 65)
                        self.log(f"{pair} per-minute limit; sleeping {wait}s")
                        time.sleep(wait)
                        continue
                    if e.code in (400, 404):
                        if e.code == 404 or "not supported" in txt or "is not found" in txt:
                            self.dead[pair] = f"{e.code}"; self._save()
                        self.log(f"{pair} HTTP {e.code}: {txt[:160]}")
                        if e.code == 400 and "not supported" not in txt:
                            raise  # a real request bug; surface it
                        break
                    self.log(f"{pair} HTTP {e.code}; next")
                    break
                except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                    self.log(f"{pair} {type(e).__name__}: {e}; next")
                    break
        raise PoolExhausted("all pairs failed for this request")

    def json_call(self, system: str, user: str, schema: dict, exclude_models=(), prefer_model=None) -> tuple[dict, str]:
        """Single-shot structured call -> (parsed_json, model)."""
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {"responseMimeType": "application/json", "responseJsonSchema": schema, "temperature": 0},
        }
        for _ in range(3):
            data, model = self.generate(body, exclude_models, prefer_model)
            text = "".join(p.get("text", "") for p in data["candidates"][0]["content"].get("parts", []) if not p.get("thought"))
            try:
                return json.loads(text), model
            except json.JSONDecodeError:
                m = re.search(r"\{.*\}", text, re.S)  # models without strict JSON mode (gemma)
                if m:
                    try:
                        return json.loads(m.group(0)), model
                    except json.JSONDecodeError:
                        pass
                self.log(f"{model} returned non-JSON; retrying on another model")
                exclude_models = tuple(exclude_models) + (model,)
        raise PoolExhausted("no model returned valid JSON")


if __name__ == "__main__":
    p = GeminiPool()
    out, m = p.json_call("Answer in JSON.", "Say ok.", {"type": "object", "properties": {"ok": {"type": "string"}}, "required": ["ok"]})
    print(m, out)
