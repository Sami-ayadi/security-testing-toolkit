const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

const state = {
  correlation: createCorrelation(),
  events: []
};

function createCorrelation() {
  return `case-${crypto.randomUUID().slice(0, 8)}`;
}

function setMessage(text, kind = "info") {
  const message = $("#csrf-message");
  message.textContent = text;
  message.className = `message ${kind}`;
}

async function generatePoc() {
  setMessage("Génération…");
  try {
    const response = await fetch("/api/csrf/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        raw: $("#raw-request").value,
        options: {
          autoSubmit: $("#auto-submit").checked,
          fileMode: $("#file-mode").value
        }
      })
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Impossible de générer la PoC.");
    $("#poc-output").value = result.html;
    $("#copy-poc").disabled = false;
    $("#download-poc").disabled = false;
    setMessage(result.warning || "PoC générée. Vérifiez toujours son comportement sur un environnement autorisé.", result.warning ? "warning" : "success");
  } catch (error) {
    setMessage(error.message, "error");
  }
}

function downloadPoc() {
  const blob = new Blob([$("#poc-output").value], { type: "text/html" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "csrf-poc.html";
  link.click();
  URL.revokeObjectURL(link.href);
}

function tokenIsValid(token) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(token);
}

function updateEndpoints() {
  const token = $("#token").value.trim();
  if (!tokenIsValid(token)) {
    $("#http-endpoint").textContent = "Configurez un token valide";
    $("#dns-endpoint").textContent = "Configurez un token valide";
    $("#email-endpoint").textContent = "Configurez un token valide";
    return;
  }
  $("#http-endpoint").textContent = `https://webhook.site/${token}/${state.correlation}`;
  $("#dns-endpoint").textContent = `${state.correlation}.${token}.dnshook.site`;
  $("#email-endpoint").textContent = `${token}@emailhook.site`;
  sessionStorage.setItem("webhook-token", token);
}

function formatDate(value) {
  if (!value) return "Date inconnue";
  return new Intl.DateTimeFormat("fr-FR", { dateStyle: "short", timeStyle: "medium" }).format(new Date(value));
}

function eventSummary(event) {
  if (event.type === "dns") return event.hostname || event.content || "Requête DNS";
  if (event.type === "email") return event.subject || event.sender || "E-mail reçu";
  return `${event.method || "HTTP"} ${event.url || ""}`;
}

function renderEvents() {
  const container = $("#events");
  $("#event-count").textContent = `${state.events.length} événement${state.events.length === 1 ? "" : "s"}`;
  if (!state.events.length) {
    container.className = "events empty";
    container.textContent = "Aucune interaction reçue.";
    return;
  }
  container.className = "events";
  container.replaceChildren(...state.events.map((event) => {
    const item = document.createElement("details");
    const summary = document.createElement("summary");
    const badge = document.createElement("span");
    const description = document.createElement("strong");
    const time = document.createElement("time");
    const pre = document.createElement("pre");
    badge.className = `event-type ${event.type || "web"}`;
    badge.textContent = (event.type || "web").toUpperCase();
    description.textContent = eventSummary(event);
    time.textContent = formatDate(event.created_at);
    pre.textContent = JSON.stringify(event, null, 2);
    summary.append(badge, description, time);
    item.append(summary, pre);
    return item;
  }));
}

async function refreshEvents() {
  const token = $("#token").value.trim();
  if (!tokenIsValid(token)) {
    setOastStatus("Token invalide", "error");
    return;
  }
  setOastStatus("Chargement…", "loading");
  try {
    const headers = {};
    const apiKey = $("#api-key").value.trim();
    if (apiKey) headers["X-Webhook-Api-Key"] = apiKey;
    const response = await fetch(`/api/oast/${encodeURIComponent(token)}`, { headers });
    const result = await response.json();
    if (!response.ok) throw new Error(result.message || result.error || `Erreur HTTP ${response.status}`);
    const items = Array.isArray(result) ? result : result.data || [];
    state.events = items;
    renderEvents();
    setOastStatus("Connecté", "success");
  } catch (error) {
    setOastStatus(error.message, "error");
  }
}

function setOastStatus(text, kind) {
  const status = $("#oast-status");
  status.textContent = text;
  status.className = `status ${kind}`;
}

$$('.tab').forEach((tab) => tab.addEventListener("click", () => {
  $$('.tab').forEach((candidate) => candidate.classList.toggle("active", candidate === tab));
  $$('.panel').forEach((panel) => panel.classList.toggle("active", panel.id === tab.dataset.panel));
}));

$("#generate").addEventListener("click", generatePoc);
$("#clear-request").addEventListener("click", () => { $("#raw-request").value = ""; });
$("#copy-poc").addEventListener("click", () => navigator.clipboard.writeText($("#poc-output").value));
$("#download-poc").addEventListener("click", downloadPoc);
$("#token").addEventListener("input", updateEndpoints);
$("#new-correlation").addEventListener("click", () => { state.correlation = createCorrelation(); updateEndpoints(); });
$("#refresh-events").addEventListener("click", refreshEvents);
$$('.copy-small').forEach((button) => button.addEventListener("click", () => {
  navigator.clipboard.writeText($(`#${button.dataset.copy}`).textContent);
  button.textContent = "Copié";
  setTimeout(() => { button.textContent = "Copier"; }, 1200);
}));

$("#token").value = sessionStorage.getItem("webhook-token") || "";
updateEndpoints();
