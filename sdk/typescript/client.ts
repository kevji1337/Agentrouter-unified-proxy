export class AgentRouterClient {
  constructor(private baseURL: string, private apiKey: string) {
    this.baseURL = baseURL.replace(/\/$/, "")
  }

  async request<T>(path: string, body?: unknown, method = "POST"): Promise<T> {
    const response = await fetch(this.baseURL + path, {
      method,
      headers: { Authorization: `Bearer ${this.apiKey}`, "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
    if (!response.ok) throw new Error(`AgentRouter HTTP ${response.status}: ${await response.text()}`)
    return response.json() as Promise<T>
  }

  chat(model: string, messages: Array<Record<string, unknown>>) {
    return this.request("/v1/chat/completions", { model, messages })
  }

  responses(model: string, input: unknown) {
    return this.request("/v1/responses", { model, input })
  }

  models() { return this.request("/v1/models", undefined, "GET") }
}
