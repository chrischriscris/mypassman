"use strict";

(() => {
  const data = globalThis.MPM_ATLAS;
  const content = document.getElementById("content");
  const storageKey = "mypassman-atlas-drafts-v1";
  const escape = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
  const link = (label, href) => `<a href="${escape(href)}">${escape(label)}</a>`;
  const pill = (label) => `<span class="pill ${escape(label.toLowerCase().replaceAll(" ", "-"))}">${escape(label)}</span>`;
  const statusLabel = (status) => ({ "not-started": "Not started", "in-progress": "In progress", implemented: "Implemented", verified: "Verified" })[status];
  let drafts = {};
  let storageAvailable = true;
  let scenarioId = data.scenarios[0].id;
  let step = 0;

  try {
    const saved = JSON.parse(localStorage.getItem(storageKey) || "{}");
    for (const decision of data.decisions) {
      const draft = saved?.[decision.id];
      if (draft && typeof draft.note === "string" && (draft.choice === "" || decision.options.includes(draft.choice))) {
        drafts[decision.id] = { choice: draft.choice, note: draft.note.slice(0, 2000), updated: typeof draft.updated === "string" ? draft.updated : "" };
      }
    }
  } catch { storageAvailable = false; }

  function feedback(message) { document.getElementById("feedback").textContent = message; }
  function persistDrafts() {
    try { localStorage.setItem(storageKey, JSON.stringify(drafts)); storageAvailable = true; }
    catch { storageAvailable = false; }
  }
  function heading(label, title, description) {
    return `<p class="eyebrow">${escape(label)}</p><h1>${escape(title)}</h1><p class="lede">${escape(description)}</p>`;
  }
  function overview() {
    return `${heading("An understandable rebuild", "The whole system, in view.", "Explore a system, work through a failure, and see which decisions still need evidence.")}
      <div class="row">${pill("Design phase")}<span class="small muted">Snapshot · ${escape(data.updated)} · ${escape(data.baseline)}</span></div>
      <p class="note">${escape(data.scope)}</p>
      <section class="section" aria-labelledby="map-title"><div class="row between"><h2 id="map-title">The system map</h2><span class="small muted">Select a component to explore it</span></div>
        <div class="map">
          <div class="device"><div class="device-label">Your device · trusted client</div>
            <a class="node" href="#system/clients"><strong>Interface & autofill</strong><small>Platform behavior and selected plaintext</small></a>
            <div class="connector" aria-hidden="true">↕</div>
            <a class="node engine" href="#system/core"><strong>Rust vault engine</strong><small>One shared set of vault rules</small></a>
            <div class="connector" aria-hidden="true">↕</div>
            <div class="node-pair"><a class="node" href="#system/storage"><strong>Local storage</strong><small>Encrypted durable state</small></a><a class="node" href="#system/keys"><strong>Protected keys</strong><small>Authority stays on clients</small></a></div>
          </div>
          <div class="bridge" aria-hidden="true">⇄</div>
          <div class="remote"><a class="node" href="#system/hosting"><strong>Blind hosting service</strong><small>Encrypted content + access metadata</small></a><a class="node" href="#system/sync"><strong>Another authorized device</strong><small>Validates changes before accepting them</small></a></div>
        </div><p class="map-caption">Clients exchange encrypted changes and files through the service. Local access continues for content already present.</p>
      </section>
      <div class="split section"><section><h2>Next, in order</h2><ol class="steps">
        <li><div><strong>Make the state model concrete</strong><p>Revisions, keys, authorization, recovery, compatibility.</p></div></li>
        <li><div><strong>Prove two-device behavior</strong><p>Offline edits, interruption, replay, revocation, and rollback.</p></div></li>
        <li><div><strong>Build one usable path</strong><p>One client and one host, with measured resource use.</p></div></li>
      </ol></section><section><h2>Keep the foundations visible</h2><ul class="simple-list">
        <li>${link("Product requirements", "../PRODUCT-BRIEF.md")}</li>
        <li>${link("Current architecture proposal", "../ARCHITECTURE-PROPOSAL.md")}</li>
        <li>${link("Independent review and qualifications", "../reviews/2026-10-04-opus-5-5.md")}</li>
        <li>${link("Upstream reference repositories", "../REFERENCES.md")}</li>
      </ul><a class="button" href="#lab">Walk through a sync failure →</a></section></div>`;
  }
  function systemPage(system) {
    const sections = [["What it owns", system.owns], ["Where the boundary is", system.boundary], ["What can go wrong", system.failure], ["Next concrete step", system.next]];
    return `${heading(system.tag, system.name, system.purpose)}
      <div class="row"><span class="small muted">Design</span>${pill(system.design)}<span class="small muted">Delivery</span>${pill(statusLabel(system.implementation))}</div>
      <div class="flow" aria-label="Proposed flow">${system.flow.map((text, i) => `${i ? '<span class="flow-arrow" aria-hidden="true">→</span>' : ""}<div class="flow-node">${escape(text)}</div>`).join("")}</div>
      <div class="detail-grid">${sections.map(([title, body]) => `<section><h2>${title}</h2><p>${escape(body)}</p></section>`).join("")}</div>
      <section class="panel section"><p class="eyebrow">Verification target</p><h2>What would count as evidence?</h2><p>${escape(system.done)}</p><p class="small muted">${system.evidence.length ? system.evidence.map((item) => link(item.label, item.href)).join(" · ") : "No replacement implementation evidence recorded yet."}</p></section>
      <div class="split section"><section><h2>Related decisions</h2><ul class="simple-list">${system.decisions.map((id) => { const item = data.decisions.find((entry) => entry.id === id); return `<li>${link(item.title, `#decisions/${id}`)}<span class="small muted">${escape(item.status)} · ${escape(item.timing)}</span></li>`; }).join("")}</ul></section>
      <section><h2>Sources & reference code</h2><p class="small muted">Existing code links are reference material, not proof that the proposed design is implemented.</p><ul class="simple-list">${system.sources.map((source) => `<li>${link(source.label, source.href)}${source.archivePath ? `<small class="muted">Archive path: <code>${escape(source.archivePath)}</code></small>` : ""}</li>`).join("")}</ul></section></div>`;
  }
  function decisionPage(selectedId) {
    return `${heading("Record the reason, not just the choice", "Decisions with a history.", "Chosen decisions are recorded in the project. Open questions stay visible until we resolve them.")}
      <div class="row between"><p class="small muted">Drafts below stay in this browser. Export them for review and recording in the repository.</p><button type="button" id="export-drafts" ${Object.keys(drafts).length ? "" : "disabled"}>Export drafts</button></div>
      ${!storageAvailable ? '<p class="note">Browser storage is unavailable. Drafts last only for this page session; export them before leaving.</p>' : ""}
      ${data.decisions.map((decision) => {
        const draft = drafts[decision.id];
        const editable = decision.status !== "Chosen";
        return `<article class="decision" id="decision-${decision.id}"><div class="decision-head"><h2>${escape(decision.title)}</h2><div class="row">${pill(decision.status)}<span class="small muted">${escape(decision.timing)}</span></div></div>
          ${decision.choice ? `<p><strong>${escape(decision.choice)}</strong></p>` : ""}<p class="muted">${escape(decision.why)}</p><p class="small">${link("Read the recorded context", decision.source)}</p>
          ${editable ? `<details ${selectedId === decision.id || draft ? "open" : ""}><summary>${draft ? "Review your saved draft" : "Draft a preference or question"}</summary><form data-decision="${decision.id}">
            <label class="field">Preference<select name="choice"><option value="">No preference yet</option>${decision.options.map((option) => `<option ${draft?.choice === option ? "selected" : ""}>${escape(option)}</option>`).join("")}</select></label>
            <label class="field">Reason or question<textarea name="note" maxlength="2000" placeholder="What matters to you about this decision?">${escape(draft?.note || "")}</textarea></label>
            <div class="row"><button class="primary" type="submit">Save draft</button>${draft ? `<button type="button" data-discard="${decision.id}">Discard draft</button>` : ""}<span class="small muted">A draft does not change the project's decision.</span></div>
          </form></details>` : ""}</article>`;
      }).join("")}`;
  }
  function labPage() {
    const scenario = data.scenarios.find((item) => item.id === scenarioId);
    const current = scenario.steps[step];
    return `${heading("Explore the behavior", "What happens when…", "Step through the intended behavior of two devices and a blind relay.")}
      <p class="note">Conceptual walkthrough with fictional revisions. This does not execute cryptography, test code, or establish that the protocol is correct.</p>
      <div class="toolbar"><label class="field">Scenario<select id="scenario">${data.scenarios.map((item) => `<option value="${item.id}" ${item.id === scenarioId ? "selected" : ""}>${escape(item.title)}</option>`).join("")}</select></label><a href="#system/sync" class="small">Explore the sync system →</a></div>
      <section class="panel lab-stage" aria-label="Scenario state"><div class="row between"><h2 id="step-title">${escape(current.title)}</h2><span class="lab-step">Step ${step + 1} of ${scenario.steps.length}</span></div>
        <div class="lab-lanes"><div class="lab-lane"><h3>Device A</h3><p>${escape(current.a)}</p></div><div class="lab-lane relay"><h3>Blind relay</h3><p>${escape(current.relay)}</p></div><div class="lab-lane"><h3>Device B</h3><p>${escape(current.b)}</p></div></div>
        <p class="muted">${escape(current.note)}</p><div class="row between"><button type="button" id="previous" ${step === 0 ? "disabled" : ""}>← Previous</button><button type="button" class="primary" id="next" ${step === scenario.steps.length - 1 ? "disabled" : ""}>Next step →</button></div>
      </section>`;
  }
  function evidencePage() {
    return `${heading("Claims need something behind them", "Evidence, not percentages.", "Track what changed, what was checked, and which revision the result applies to.")}
      <p class="note">Manually maintained snapshot: ${escape(data.baseline)}. This page does not scan Git, run tests, or update itself from build results.</p>
      <div class="table-wrap"><table><caption class="small muted">Delivery status of the proposed replacement</caption><thead><tr><th scope="col">System</th><th scope="col">Delivery</th><th scope="col">Evidence</th></tr></thead><tbody>${data.systems.map((system) => `<tr><th scope="row">${link(system.name, `#system/${system.id}`)}</th><td>${pill(statusLabel(system.implementation))}</td><td>${system.evidence.length ? system.evidence.map((item) => link(item.label, item.href)).join(" · ") : "None recorded"}</td></tr>`).join("")}</tbody></table></div>
      <section class="section"><h2>How status earns its name</h2><ol class="steps"><li><div><strong>In progress</strong><p>A scoped change has actually started; identify the work and remaining checks.</p></div></li><li><div><strong>Implemented</strong><p>Link the code and record the behavior that exists, including known gaps.</p></div></li><li><div><strong>Verified</strong><p>Attach a meaningful check, result, date, and exact code revision. Passing tests do not constitute a security audit.</p></div></li></ol></section>
      <section class="section"><h2>Activity</h2><ol class="timeline">${data.activity.map((item) => `<li><time datetime="${item.date}">${item.date}</time><div><h3>${escape(item.title)}</h3>${pill(item.kind)}<p>${escape(item.detail)}</p>${item.href ? link("Open record", item.href) : ""}</div></li>`).join("")}</ol></section>`;
  }
  function render(moveFocus = false) {
    const [page, id] = location.hash.slice(1).split("/");
    if (page === "content") { content.focus(); return; }
    let title = "Overview";
    if (page === "system") {
      const system = data.systems.find((item) => item.id === id);
      content.innerHTML = system ? systemPage(system) : `${heading("Unknown system", "This chapter does not exist.", "Return to the overview to find a system.")}<a href="#overview">Open overview</a>`;
      title = system?.name || "Unknown system";
    } else if (page === "decisions") { content.innerHTML = decisionPage(id); title = "Decisions"; }
    else if (page === "lab") { content.innerHTML = labPage(); title = "Walkthroughs"; }
    else if (page === "evidence") { content.innerHTML = evidencePage(); title = "Evidence & history"; }
    else { content.innerHTML = overview(); }
    document.getElementById("breadcrumb").textContent = title;
    document.title = `${title} · mypassman atlas`;
    for (const anchor of document.querySelectorAll("nav a")) {
      const active = anchor.hash === (page === "decisions" ? "#decisions" : location.hash || "#overview");
      if (active) anchor.setAttribute("aria-current", "page"); else anchor.removeAttribute("aria-current");
    }
    if (moveFocus) { content.focus({ preventScroll: true }); window.scrollTo(0, 0); }
    if (page === "decisions" && id) document.getElementById(`decision-${id}`)?.scrollIntoView({ block: "start" });
  }
  document.getElementById("system-nav").innerHTML = data.systems.map((system) => link(system.name, `#system/${system.id}`)).join("");
  document.getElementById("snapshot").textContent = `Snapshot · ${data.updated}`;
  window.addEventListener("hashchange", () => { feedback(""); render(true); });
  content.addEventListener("submit", (event) => {
    const form = event.target.closest("form[data-decision]");
    if (!form) return;
    event.preventDefault();
    const values = new FormData(form);
    const decision = data.decisions.find((item) => item.id === form.dataset.decision);
    const choice = String(values.get("choice"));
    if (!decision || (choice && !decision.options.includes(choice))) return;
    drafts[decision.id] = { choice, note: String(values.get("note")).slice(0, 2000), updated: new Date().toISOString() };
    persistDrafts();
    const scroll = window.scrollY;
    render(); window.scrollTo(0, scroll);
    content.querySelector(`[data-decision="${decision.id}"] button[type="submit"]`)?.focus({ preventScroll: true });
    feedback(storageAvailable ? "Draft saved in this browser. The project decision is unchanged; export the draft for review." : "Browser storage unavailable. Export your draft before leaving this page.");
  });
  content.addEventListener("change", (event) => {
    if (event.target.id === "scenario") {
      scenarioId = event.target.value; step = 0; render();
      document.getElementById("scenario").focus({ preventScroll: true });
      feedback(`Scenario: ${data.scenarios.find((item) => item.id === scenarioId).title}. Step 1.`);
    }
  });
  content.addEventListener("click", (event) => {
    const button = event.target.closest("button");
    if (!button) return;
    if (button.id === "next" || button.id === "previous") {
      const scenario = data.scenarios.find((item) => item.id === scenarioId);
      step = Math.max(0, Math.min(scenario.steps.length - 1, step + (button.id === "next" ? 1 : -1)));
      render();
      const focusId = step === scenario.steps.length - 1 ? "previous" : step === 0 ? "next" : button.id;
      document.getElementById(focusId).focus({ preventScroll: true });
      feedback(`Step ${step + 1}: ${scenario.steps[step].title}. ${scenario.steps[step].note}`);
    } else if (button.dataset.discard) {
      const id = button.dataset.discard;
      delete drafts[id]; persistDrafts(); render();
      document.querySelector(`#decision-${id} summary`)?.focus({ preventScroll: true });
      feedback("Local draft discarded.");
    } else if (button.id === "export-drafts") {
      const blob = new Blob([JSON.stringify({ schemaVersion: 1, kind: "decision-drafts", sourceSnapshot: data.updated, exportedAt: new Date().toISOString(), drafts }, null, 2) + "\n"], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url; anchor.download = "mypassman-decision-drafts.json"; anchor.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      feedback("Draft export downloaded. Review and record accepted decisions in the project; this export is not an approval record.");
    }
  });
  render();
})();
