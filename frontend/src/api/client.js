/**
 * frontend/src/api/client.js
 * ──────────────────────────
 * REST API client with intelligent multi-host fallback (Cloud Run, Localhost, Proxy).
 */

const DEFAULT_KEY = "test_secret_key_12345678901234567890123456789012";
export const CLOUD_RUN_URL = "https://bugbounty-swarm-backend-kva52deviq-uc.a.run.app";


function sanitizeKey(key) {
  if (!key) return DEFAULT_KEY;
  const cleaned = key.replace(/^[= "']+/, "").replace(/[ "']+$/, "").trim();
  return cleaned.length > 10 ? cleaned : DEFAULT_KEY;
}

export class SwarmApiClient {
  constructor(baseUrl, apiKey) {
    this.customBaseUrl = baseUrl || localStorage.getItem("swarm_backend_url") || "";
    this.apiKey = sanitizeKey(apiKey || localStorage.getItem("swarm_api_key"));
  }

  setBaseUrl(url) {
    this.customBaseUrl = url.trim().replace(/\/$/, "");
    localStorage.setItem("swarm_backend_url", this.customBaseUrl);
  }

  getBaseUrl() {
    return this.customBaseUrl;
  }

  setApiKey(key) {
    this.apiKey = sanitizeKey(key);
    localStorage.setItem("swarm_api_key", this.apiKey);
  }

  _getHeaders() {
    return {
      "Content-Type": "application/json",
      "X-API-Key": sanitizeKey(this.apiKey),
    };
  }

  /** Fetch runtime config from backend at startup */
  async fetchConfig() {
    const candidateHosts = [
      this.customBaseUrl,
      "http://127.0.0.1:8000",
      CLOUD_RUN_URL,
      "http://localhost:8000",
      "",
    ].filter(Boolean);

    for (const host of candidateHosts) {
      try {
        const url = `${host}/api/config`;
        const resp = await fetch(url);
        if (resp.ok) {
          const cfg = await resp.json();
          if (cfg.api_key) {
            this.setApiKey(cfg.api_key);
          }
          return { ...cfg, connectedHost: host };
        }
      } catch (_) { /* try next host */ }
    }
    return null;
  }

  /** Fetch Agent Registry Catalog from backend */
  async fetchAgentRegistry() {
    return await this._fetchWithFallback("/api/agents");
  }

  async _fetchWithFallback(path, options = {}) {
    const candidateHosts = [
      this.customBaseUrl,
      "http://127.0.0.1:8000",
      CLOUD_RUN_URL,
      "http://localhost:8000",
      "",
    ].filter(Boolean);

    let lastError = null;

    for (const host of candidateHosts) {
      const url = `${host}${path}`;
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
        if (err.message && (err.message.startsWith("HTTP") || err.message.includes("Target") || err.message.includes("API key"))) {
          throw err;
        }
      }
    }
    throw lastError || new Error("Cannot connect to backend API server");
  }

  async createInvestigation(payload) {
    const body = typeof payload === "string" ? { target_url: payload } : payload;
    return await this._fetchWithFallback("/investigations", {
      method: "POST",
      headers: this._getHeaders(),
      body: JSON.stringify(body),
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
