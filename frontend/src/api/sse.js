/**
 * frontend/src/api/sse.js
 * ───────────────────────
 * Resilient Server-Sent Events client with:
 * - Automatic reconnection with exponential backoff
 * - Sequence-number deduplication
 * - Last-Event-ID tracking across reconnects
 * - Authentication header / token support
 */

export class InvestigationEventClient {
  constructor(baseUrl, apiKey, onEvent, onError, onStatusChange) {
    this.baseUrl = baseUrl ? baseUrl.replace(/\/$/, "") : "http://127.0.0.1:8000";
    this.apiKey = apiKey;
    this.onEvent = onEvent || (() => {});
    this.onError = onError || (() => {});
    this.onStatusChange = onStatusChange || (() => {});

    this.lastSequenceNumber = 0;
    this.seenEventIds = new Set();
    this.investigationId = null;
    this.eventSource = null;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 10;
    this.isExplicitlyClosed = false;
    this.reconnectTimer = null;
  }

  connect(investigationId, initialLastSeq = 0) {
    this.investigationId = investigationId;
    this.lastSequenceNumber = initialLastSeq || this.lastSequenceNumber;
    this.isExplicitlyClosed = false;
    this._startConnection();
  }

  _startConnection() {
    if (this.isExplicitlyClosed || !this.investigationId) return;

    // Use Fetch API + ReadableStream to support custom X-API-Key and Last-Event-ID headers
    const url = this.baseUrl
      ? `${this.baseUrl}/investigations/${this.investigationId}/stream?last_seq=${this.lastSequenceNumber}`
      : `/investigations/${this.investigationId}/stream?last_seq=${this.lastSequenceNumber}`;

    this.onStatusChange("CONNECTING");

    const headers = {
      "Accept": "text/event-stream",
    };
    if (this.apiKey) {
      headers["X-API-Key"] = this.apiKey;
    }
    if (this.lastSequenceNumber > 0) {
      headers["Last-Event-ID"] = String(this.lastSequenceNumber);
    }

    const controller = new AbortController();
    this.abortController = controller;

    fetch(url, {
      method: "GET",
      headers: headers,
      signal: controller.signal,
    })
      .then((response) => {
        if (!response.ok) {
          throw new Error(`SSE HTTP error: ${response.status} ${response.statusText}`);
        }
        this.reconnectAttempts = 0;
        this.onStatusChange("CONNECTED");
        return this._readStream(response.body.getReader());
      })
      .catch((err) => {
        if (this.isExplicitlyClosed) return;
        this.onStatusChange("DISCONNECTED");
        this.onError(err);
        this._scheduleReconnect();
      });
  }

  async _readStream(reader) {
    const decoder = new TextDecoder();
    let buffer = "";

    while (!this.isExplicitlyClosed) {
      const { value, done } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop(); // Keep partial line in buffer

      let currentEvent = { id: null, event: "message", data: "" };

      for (const line of lines) {
        if (line.startsWith(":")) {
          // Comment / keepalive line
          continue;
        } else if (line.startsWith("id:")) {
          currentEvent.id = line.replace(/^id:\s*/, "").trim();
        } else if (line.startsWith("event:")) {
          currentEvent.event = line.replace(/^event:\s*/, "").trim();
        } else if (line.startsWith("data:")) {
          currentEvent.data += line.replace(/^data:\s*/, "") + "\n";
        } else if (line === "") {
          // Dispatch full event block
          if (currentEvent.data) {
            this._handleParsedEvent(currentEvent);
          }
          currentEvent = { id: null, event: "message", data: "" };
        }
      }
    }
  }

  _handleParsedEvent(sseEvent) {
    try {
      const payload = JSON.parse(sseEvent.data.trim());

      // Sequence & ID Deduplication
      if (payload.sequence_number) {
        if (payload.sequence_number <= this.lastSequenceNumber) {
          return; // Skip already processed sequence
        }
        this.lastSequenceNumber = payload.sequence_number;
      }

      if (payload.event_id) {
        if (this.seenEventIds.has(payload.event_id)) {
          return;
        }
        this.seenEventIds.add(payload.event_id);
      }

      this.onEvent(payload);
    } catch (err) {
      console.warn("Failed to parse SSE payload:", err, sseEvent.data);
    }
  }

  _scheduleReconnect() {
    if (this.isExplicitlyClosed) return;
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      this.onError(new Error("Max SSE reconnect attempts reached"));
      return;
    }

    const backoffMs = Math.min(1000 * Math.pow(1.5, this.reconnectAttempts), 15000);
    this.reconnectAttempts++;
    this.onStatusChange("RECONNECTING");

    this.reconnectTimer = setTimeout(() => {
      this._startConnection();
    }, backoffMs);
  }

  disconnect() {
    this.isExplicitlyClosed = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }
    if (this.abortController) {
      this.abortController.abort();
    }
    this.onStatusChange("DISCONNECTED");
  }
}
