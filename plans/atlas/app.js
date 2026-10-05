"use strict";

(() => {
  const data = globalThis.MPM_ATLAS;
  const content = document.getElementById("content");
  const views = ["map", "decisions", "walkthroughs", "log"];
  const escape = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
  const link = (label, href) => `<a href="${escape(href)}">${escape(label)}</a>`;
  const byId = (items, id) => items.find((item) => item.id === id);
  const statusLabel = (status) => ({ "not-started": "Not started", "in-progress": "In progress", implemented: "Implemented", verified: "Verified" })[status];
  const levels = { Open: "l0", "Not started": "l0", Deferred: "l0", Proposed: "l1", "In progress": "l1", Implemented: "l2", Chosen: "l3", Verified: "l3" };
  const ring = (status) => `<span class="ring ${levels[status]}" aria-hidden="true"></span>`;
  const status = (value) => `<span class="status">${ring(value)}${escape(value)}</span>`;
  const reducedMotion = () => matchMedia("(prefers-reduced-motion: reduce)").matches;

  function route() {
    const [view, id, step] = location.hash.slice(1).split("/");
    return views.includes(view) ? { view, id, step } : { view: "map" };
  }
  function feedback(message) { document.getElementById("feedback").textContent = message; }

  function mapNode(id, selected) {
    const system = byId(data.systems, id);
    const active = system.id === selected;
    return `<a class="node" data-id="${system.id}" href="#map${active ? "" : `/${system.id}`}"${active ? ' aria-current="true"' : ""}><strong>${escape(system.name)}${ring(system.design)}<span class="visually-hidden">, design ${escape(system.design.toLowerCase())}</span></strong><small>${escape(system.tag)}</small></a>`;
  }
  function mapView(id) {
    const system = byId(data.systems, id);
    const { map } = data.overview;
    const node = (nodeId) => mapNode(nodeId, system?.id);
    const wire = '<span class="wire-v" aria-hidden="true"></span>';
    return `<div class="workspace">
      <section class="canvas" aria-labelledby="canvas-title">
        <div class="canvas-head"><h1 id="canvas-title">System map</h1><p>Select a system to see its details.</p></div>
        <div class="map">
          <div class="map-field">
            <div class="zone"><p class="zone-label">Your device</p>${map.processes.map(node).join(wire)}${wire}<div class="stores">${map.stores.map(node).join("")}</div></div>
            <div class="outside">
              <div class="crossing"><span class="wire-h" aria-hidden="true"></span>${wire}${node(map.exchange)}<small>Encrypted changes</small></div>
              <div class="service">${map.service.map(node).join("")}</div>
              <div class="peer">${wire}<div class="zone"><p class="zone-label">Another authorized device</p><p>Validates changes before accepting them.</p></div></div>
            </div>
          </div>
          <div class="across"><p class="zone-label">Across every component</p><div class="across-grid">${map.across.map(node).join("")}</div></div>
          <ul class="legend">
            <li><span class="swatch trusted" aria-hidden="true"></span>Trusted: keys and plaintext stay inside</li>
            <li><span class="swatch" aria-hidden="true"></span>Outside: only ciphertext and access metadata</li>
            <li>${ring("Open")}Open ${ring("Proposed")}Proposed ${ring("Chosen")}Chosen design</li>
          </ul>
        </div>
      </section>
      <aside class="panel" aria-labelledby="panel-title">${system ? systemPanel(system) : overviewPanel()}</aside>
    </div>`;
  }
  function overviewPanel() {
    const built = data.systems.filter((system) => ["implemented", "verified"].includes(system.implementation)).length;
    const open = data.decisions.filter((decision) => decision.status === "Open").length;
    return `<h2 id="panel-title" tabindex="-1">Overview</h2>
      <p class="lede">${escape(data.product)}</p>
      <dl class="facts"><div><dt>Implemented</dt><dd>${built} of ${data.systems.length} systems</dd></div><div><dt>Open decisions</dt><dd><a href="#decisions">${open}</a></dd></div><div><dt>Snapshot</dt><dd>${escape(data.updated)}</dd></div></dl>
      <p class="muted note">${escape(data.scope)}</p>
      <section><h3>Next, in order</h3><ol class="steps">${data.overview.next.map((item) => `<li><div><strong>${escape(item.title)}</strong><p>${escape(item.detail)}</p></div></li>`).join("")}</ol></section>
      <section><h3>Project records</h3><ul class="links">${data.overview.foundations.map((item) => `<li>${link(item.label, item.href)}</li>`).join("")}<li>${link("How to keep this atlas current", "README.md")}</li></ul></section>`;
  }
  function systemPanel(system) {
    const index = data.systems.indexOf(system);
    const previous = data.systems[(index - 1 + data.systems.length) % data.systems.length];
    const next = data.systems[(index + 1) % data.systems.length];
    const sections = [["What it owns", system.owns], ["Where the boundary is", system.boundary], ["What can go wrong", system.failure], ["Next concrete step", system.next]];
    return `<div class="panel-top"><a class="close" href="#map" aria-label="Close ${escape(system.name)}">×</a></div>
      <h2 id="panel-title" tabindex="-1">${escape(system.name)}</h2>
      <p class="lede">${escape(system.purpose)}</p>
      <dl class="facts"><div><dt>Design</dt><dd>${status(system.design)}</dd></div><div><dt>Delivery</dt><dd>${status(statusLabel(system.implementation))}</dd></div></dl>
      <section><h3>Proposed flow</h3><ol class="flow">${system.flow.map((text) => `<li>${escape(text)}</li>`).join("")}</ol></section>
      ${sections.map(([title, body]) => `<section><h3>${title}</h3><p>${escape(body)}</p></section>`).join("")}
      <section><h3>What would count as evidence</h3><p>${escape(system.done)}</p><p class="muted">${system.evidence.length ? system.evidence.map((item) => link(item.label, item.href)).join(", ") : "No evidence recorded yet."}</p></section>
      <section><h3>Decisions</h3><ul class="links">${system.decisions.map((id) => { const decision = byId(data.decisions, id); return `<li><a href="#decisions/${id}">${escape(decision.title)}</a>${status(decision.status)}</li>`; }).join("")}</ul></section>
      <section><h3>Sources</h3><ul class="links">${system.sources.map((source) => `<li>${link(source.label, source.href)}${source.archivePath ? `<code>${escape(source.archivePath)}</code>` : ""}</li>`).join("")}</ul></section>
      <nav class="pager" aria-label="Other systems"><a href="#map/${previous.id}">← ${escape(previous.name)}</a><a href="#map/${next.id}">${escape(next.name)} →</a></nav>`;
  }

  function decisionsView(id) {
    const order = ["Open", "Proposed", "Deferred", "Chosen"];
    const selected = byId(data.decisions, id) || data.decisions.find((decision) => decision.status === "Open") || data.decisions[0];
    const groups = order.map((value) => [value, data.decisions.filter((decision) => decision.status === value)]).filter(([, items]) => items.length);
    return `<div class="workspace">
      <section class="canvas list-canvas" aria-labelledby="canvas-title">
        <div class="canvas-head"><h1 id="canvas-title">Decisions</h1><p>Open questions come first. A proposal is a recommendation, not a decision.</p></div>
        ${groups.map(([value, items]) => `<h2 class="group">${value}<span>${items.length}</span></h2><ul class="rows">${items.map((decision) => `<li><a class="row" data-id="${decision.id}" href="#decisions/${decision.id}"${decision === selected ? ' aria-current="true"' : ""}>${ring(decision.status)}<span>${escape(decision.title)}</span><small>${escape(decision.timing)}</small></a></li>`).join("")}</ul>`).join("")}
      </section>
      <aside class="panel" aria-labelledby="panel-title">${decisionPanel(selected)}</aside>
    </div>`;
  }
  function decisionPanel(decision) {
    const affected = data.systems.filter((system) => system.decisions.includes(decision.id));
    return `<p class="panel-status">${status(decision.status)}<span class="muted">${escape(decision.timing)}</span></p>
      <h2 id="panel-title" tabindex="-1">${escape(decision.title)}</h2>
      ${decision.choice ? `<p class="choice">${escape(decision.choice)}</p>` : ""}
      <p>${escape(decision.why)}</p>
      ${decision.options.length ? `<section><h3>Options</h3><ul class="bullets">${decision.options.map((option) => `<li>${escape(option)}</li>`).join("")}</ul></section>` : ""}
      ${affected.length ? `<section><h3>Affects</h3><ul class="chips">${affected.map((system) => `<li><a href="#map/${system.id}">${escape(system.name)}</a></li>`).join("")}</ul></section>` : ""}
      <p class="more">${link("Read the recorded context", decision.source)}</p>`;
  }

  function walkState(at) {
    const scenario = byId(data.scenarios, at.id) || data.scenarios[0];
    const step = Math.max(0, Math.min(scenario.steps.length - 1, (Number.parseInt(at.step, 10) || 1) - 1));
    return { scenario, step };
  }
  function walkthroughsView(at) {
    const { scenario, step } = walkState(at);
    const shown = scenario.steps[step];
    const previous = scenario.steps[step - 1];
    const lane = (key, label, kind) => {
      const changed = previous && previous[key] !== shown[key];
      return `<div class="lane ${kind}${changed ? " changed" : ""}"><h3>${label}${changed ? '<span class="changed-tag">Changed</span>' : ""}</h3><p>${escape(shown[key])}</p></div>`;
    };
    return `<section class="page wide" aria-labelledby="page-title">
      <div class="page-head"><h1 id="page-title">Walkthroughs</h1><p class="lede">Step through the intended behavior of two devices and a blind relay.</p></div>
      <div class="segmented" role="group" aria-label="Scenario">${data.scenarios.map((item) => `<button type="button" data-scenario="${item.id}" aria-pressed="${item === scenario}">${escape(item.title)}</button>`).join("")}</div>
      <div class="stage">
        <div class="stage-head"><h2 id="step-title">${escape(shown.title)}</h2><ol class="dots" aria-label="Steps">${scenario.steps.map((item, i) => `<li${i < step ? ' class="done"' : ""}><button type="button" data-step="${i}" aria-label="Step ${i + 1}: ${escape(item.title)}"${i === step ? ' aria-current="step"' : ""}>${i + 1}</button></li>`).join("")}</ol></div>
        <div class="lanes">${lane("a", "Device A", "trusted")}${lane("relay", "Blind relay", "relay")}${lane("b", "Device B", "trusted")}</div>
        <p class="step-note">${escape(shown.note)}</p>
        <div class="controls"><button type="button" id="previous" aria-keyshortcuts="ArrowLeft"${step === 0 ? " disabled" : ""}>Previous</button><button type="button" class="primary" id="next" aria-keyshortcuts="ArrowRight"${step === scenario.steps.length - 1 ? " disabled" : ""}>Next</button></div>
      </div>
      <p class="footnote">Conceptual walkthrough with fictional revisions. It does not execute cryptography, test code, or establish that the protocol is correct. ${link("Read the sync chapter", "#map/sync")}</p>
    </section>`;
  }
  function showStep(scenario, step) {
    history.replaceState(null, "", `#walkthroughs/${scenario.id}/${step + 1}`);
    current = render();
  }
  function goToStep(target, focus) {
    const { scenario, step } = walkState(route());
    target = Math.max(0, Math.min(scenario.steps.length - 1, target));
    if (target === step) return;
    showStep(scenario, target);
    const element = focus && content.querySelector(focus);
    (element?.disabled ? document.getElementById(element.id === "next" ? "previous" : "next") : element)?.focus({ preventScroll: true });
    feedback(`Step ${target + 1}: ${scenario.steps[target].title}. ${scenario.steps[target].note}`);
  }

  function logView() {
    const ladder = [["In progress", "A scoped change has actually started; identify the work and remaining checks."], ["Implemented", "Link the code and record the behavior that exists, including known gaps."], ["Verified", "Attach a meaningful check, result, date, and exact code revision. Passing tests do not constitute a security audit."]];
    return `<section class="page" aria-labelledby="page-title">
      <div class="page-head"><h1 id="page-title">Evidence and activity</h1><p class="lede">What exists, what was checked, and when. Maintained by hand; this page does not scan Git or run tests.</p></div>
      <section><h2>Delivery</h2><ul class="status-table">${data.systems.map((system) => `<li><a href="#map/${system.id}">${escape(system.name)}</a>${status(statusLabel(system.implementation))}<span class="muted">${system.evidence.length ? system.evidence.map((item) => link(item.label, item.href)).join(", ") : "No evidence recorded"}</span></li>`).join("")}</ul></section>
      <section><h2>How status earns its name</h2><ol class="ladder">${ladder.map(([value, detail]) => `<li>${status(value)}<p>${detail}</p></li>`).join("")}</ol></section>
      <section><h2>Activity</h2><ol class="timeline">${data.activity.map((item) => `<li><time datetime="${item.date}">${item.date}</time><div><h3>${escape(item.title)}</h3><p class="kind">${escape(item.kind)}</p><p>${escape(item.detail)}</p>${item.href ? link("Open record", item.href) : ""}</div></li>`).join("")}</ol></section>
      <p class="footnote">${link("How to keep this atlas current", "README.md")}</p>
    </section>`;
  }

  function render() {
    const at = route();
    content.innerHTML = at.view === "decisions" ? decisionsView(at.id) : at.view === "walkthroughs" ? walkthroughsView(at) : at.view === "log" ? logView() : mapView(at.id);
    for (const anchor of document.querySelectorAll(".tabs a")) {
      if (anchor.hash === `#${at.view}`) anchor.setAttribute("aria-current", "page"); else anchor.removeAttribute("aria-current");
    }
    const system = at.view === "map" && byId(data.systems, at.id);
    const titles = { map: "Map", decisions: "Decisions", walkthroughs: "Walkthroughs", log: "Evidence and activity" };
    document.title = `${system ? system.name : titles[at.view]} · mypassman atlas`;
    return at;
  }
  function focusPanel() {
    const title = document.getElementById("panel-title");
    title?.focus({ preventScroll: true });
    if (matchMedia("(max-width: 999px)").matches) title?.scrollIntoView({ block: "start", behavior: reducedMotion() ? "auto" : "smooth" });
  }

  let current = render();
  window.addEventListener("hashchange", () => {
    const before = current;
    current = render();
    feedback("");
    const changedView = current.view !== before.view;
    if (changedView) window.scrollTo(0, 0);
    if (["map", "decisions"].includes(current.view) && current.id && (changedView || current.id !== before.id)) focusPanel();
    else if (!changedView && !current.id && before.id) content.querySelector(`[data-id="${before.id}"]`)?.focus();
    else content.focus({ preventScroll: true });
  });
  document.querySelector(".skip").addEventListener("click", (event) => { event.preventDefault(); content.focus(); });
  content.addEventListener("click", (event) => {
    const button = event.target.closest("button");
    if (!button) return;
    if (button.dataset.scenario) {
      const scenario = byId(data.scenarios, button.dataset.scenario);
      showStep(scenario, 0);
      content.querySelector(`[data-scenario="${scenario.id}"]`)?.focus({ preventScroll: true });
      feedback(`${scenario.title}. Step 1: ${scenario.steps[0].title}.`);
    } else if (button.id === "next" || button.id === "previous") {
      goToStep(walkState(route()).step + (button.id === "next" ? 1 : -1), `#${button.id}`);
    } else if (button.dataset.step) {
      goToStep(Number(button.dataset.step), `[data-step="${button.dataset.step}"]`);
    }
  });
  document.addEventListener("keydown", (event) => {
    if (event.altKey || event.ctrlKey || event.metaKey || event.shiftKey || event.target.closest("input, select, textarea, [contenteditable]")) return;
    const now = route();
    if (event.key === "Escape" && now.view === "map" && now.id) { location.hash = "#map"; return; }
    const delta = { ArrowLeft: -1, ArrowRight: 1 }[event.key];
    if (now.view !== "walkthroughs" || !delta) return;
    event.preventDefault();
    const target = walkState(now).step + delta;
    const active = document.activeElement;
    const focus = !content.contains(active) ? "" : active.dataset.step ? `[data-step="${target}"]` : active.dataset.scenario ? `[data-scenario="${active.dataset.scenario}"]` : active.id ? `#${active.id}` : "";
    goToStep(target, focus);
  });
})();
