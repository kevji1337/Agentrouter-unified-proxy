"""Minimal AgentRouter Unified Proxy client (Python 3.10+)."""
import json
import urllib.request


class AgentRouterClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def request(self, path: str, payload=None, method="POST"):
        data = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request) as response:
            return json.load(response)

    def chat(self, model: str, messages: list[dict]):
        return self.request("/v1/chat/completions", {"model": model, "messages": messages})

    def responses(self, model: str, input):
        return self.request("/v1/responses", {"model": model, "input": input})

    def models(self):
        return self.request("/v1/models", method="GET")
