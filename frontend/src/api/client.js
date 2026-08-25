/**
 * frontend/src/api/client.js
 * ──────────────────────────
 * REST API client with intelligent multi-host fallback (127.0.0.1, localhost, proxy).
 */

const DEFAULT_KEY = "test_secret_key_12345678901234567890123456789012";

export class SwarmApiClient {
  constructor(baseUrl, apiKey) {
    this.apiKey = apiKey || localStorage.getItem("swarm_api_key") || DEFAULT_KEY;
  }

  setApiKey(key) {
    this.apiKey = key;
    localStorage.setItem("swarm_api_key", key);
  }

  _getHeaders() {
    const headers = { "Content-Type": "application/json" };
    if (this.apiKey) {
      headers["X-API-Key"] = this.apiKey;
    }
    return headers;
  }

  async _fetchWithFallback(path, options) {
    const hosts = [
      "http://127.0.0.1:8000",
      "http://localhost:8000",
      "",
    ];
    let lastError = null;

    for (const host of hosts) {
      const url = host ? `${host}${path}` : path;
      try {
        const resp = await fetch(url, options);
        if (resp.ok) {
          return await resp.json();
        }

        // Parse backend error
        let errorMsg = `HTTP ${resp.status}`;
        try {
          const errData = await resp.json();
          if (typeof errData.message === "string") {
            errorMsg = errData.message;
          } else if (typeof errData.detail === "string") {
            errorMsg = errData.detail;
          } else if (typeof errData.detail === "object" && errData.detail !== null) {
            errorMsg = errData.detail.message || errData.detail.msg || JSON.stringify(errData.detail);
          } else if (typeof errData.error === "string") {
            errorMsg = errData.error;
          }
        } catch (_) {
          try {
            const txt = await resp.text();
            if (txt) errorMsg = txt;
          } catch (__) {}
        }
        throw new Error(errorMsg);
      } catch (err) {
        lastError = err;
        // If it's an explicit server HTTP error (like 401/403/400), don't retry other hosts
        if (err.message && err.message.startsWith("HTTP") || err.message.includes("Target") || err.message.includes("API key")) {
          throw err;
        }
      }
    }
    throw lastError || new Error("Cannot connect to backend API server at http://127.0.0.1:8000");
  }

  async createInvestigation(targetUrl) {
    return await this._fetchWithFallback("/investigations", {
      method: "POST",
      headers: this._getHeaders(),
      body: JSON.stringify({ target_url: targetUrl }),
    });
  }

  async getInvestigation(id) {
    return await this._fetchWithFallback(`/investigations/${id}`, {
      method: "GET",
      headers: this._getHeaders(),
    });
  }

  async cancelInvestigation(id) {
    return await this._fetchWithFallback(`/investigations/${id}`, {
      method: "DELETE",
      headers: this._getHeaders(),
    });
  }

  async getReport(id) {
    return await this._fetchWithFallback(`/investigations/${id}/report`, {
      method: "GET",
      headers: this._getHeaders(),
    });
  }
}
