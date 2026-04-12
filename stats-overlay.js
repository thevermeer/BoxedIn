/**
 * Overlay (isolated world): tabbed DNR + page-guard block stats and red-team
 * panels (Auth, Exfil, Inject). Listens for page-guard postMessage (same tab,
 * inc. iframes). Injected on all sites.
 */
(function () {
  "use strict";

  var POLL_MS = 4000;
  var STORAGE_VIEW_STATE = "overlayViewState";
  var STORAGE_ACTIVE_TAB = "overlayActiveTab";
  var STORAGE_REDTEAM_ENABLED = "redteamEnabled";
  var STORAGE_EXFIL_ALLOWLIST = "redteamExfilAllowlist";
  var root;
  var viewState = "normal";
  var activeTab = "blocks";
  var redteamEnabled = false;
  var exfilAllowlist = [];
  var pendingPg = { linkedInBlocklist: 0, extensionScheme: 0 };
  var pgFlushTimer = null;

  var cachedBlocksPayload = null;
  var cachedAuthData = null;
  var cachedExfilEvents = [];
  var cachedInjectData = null;
  var cachedPageGuardAuth = [];
  var exfilFilter = null;

  /* ── Page-guard stat flush ─────────────────────────────────────────── */

  function flushPendingPageGuard() {
    pgFlushTimer = null;
    var li = pendingPg.linkedInBlocklist;
    var es = pendingPg.extensionScheme;
    pendingPg.linkedInBlocklist = 0;
    pendingPg.extensionScheme = 0;
    if (li <= 0 && es <= 0) return;
    var payload = { type: "BOXEDIN_PAGE_GUARD_STAT" };
    if (li > 0) payload.linkedInBlocklist = li;
    if (es > 0) payload.extensionScheme = es;
    try {
      chrome.runtime.sendMessage(payload, function () {
        if (chrome.runtime.lastError) { /* ignore */ }
      });
    } catch (e) { /* ignore */ }
  }

  /* ── Page-guard message handler (stats + red-team events) ──────────── */

  function onPageGuardMessage(ev) {
    try {
      if (ev.origin !== window.location.origin) return;
    } catch (e) {
      return;
    }
    var data = ev.data;
    if (!data || data.source !== "boxedin-page-guard") return;

    if (data.type === "stat") {
      if (data.key === "linkedInBlocklist") {
        var d1 = typeof data.delta === "number" && data.delta > 0 ? data.delta : 1;
        pendingPg.linkedInBlocklist += d1;
      } else if (data.key === "extensionScheme") {
        var d2 = typeof data.delta === "number" && data.delta > 0 ? data.delta : 1;
        pendingPg.extensionScheme += d2;
      } else {
        return;
      }
      if (pgFlushTimer !== null) clearTimeout(pgFlushTimer);
      pgFlushTimer = setTimeout(flushPendingPageGuard, 200);
      return;
    }

    if (!redteamEnabled) return;

    if (data.type === "exfil") {
      try {
        chrome.runtime.sendMessage({
          type: "BOXEDIN_STORE_EXFIL_EVENT", event: data
        }, function () { if (chrome.runtime.lastError) {} });
      } catch (e) { /* ignore */ }
      cachedExfilEvents.push(data);
      if (cachedExfilEvents.length > 200) cachedExfilEvents = cachedExfilEvents.slice(-200);
      if (activeTab === "exfil") renderActivePanel();
      return;
    }

    if (data.type === "auth") {
      cachedPageGuardAuth.push(data);
      if (activeTab === "auth") renderActivePanel();
      return;
    }

    if (data.type === "inject") {
      try {
        chrome.runtime.sendMessage({
          type: "BOXEDIN_STORE_INJECT_FINDING", finding: data
        }, function () { if (chrome.runtime.lastError) {} });
      } catch (e) { /* ignore */ }
      if (activeTab === "inject") renderActivePanel();
      return;
    }
  }

  window.addEventListener("message", onPageGuardMessage);

  /* ── Utility ───────────────────────────────────────────────────────── */

  function isDarkUi() {
    try {
      if (document.documentElement) {
        if (document.documentElement.classList.contains("theme--dark")) return true;
        if (document.documentElement.getAttribute("data-theme") === "dark") return true;
      }
      if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) return true;
    } catch (e) { /* ignore */ }
    return false;
  }

  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function escapeAttr(s) {
    return escapeHtml(s).replace(/'/g, "&#39;");
  }

  function formatTime(ts) {
    if (!ts) return "";
    try {
      var d = new Date(ts);
      return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    } catch (e) { return ""; }
  }

  function saveViewState(state) {
    viewState = state;
    try {
      var patch = {};
      patch[STORAGE_VIEW_STATE] = state;
      chrome.storage.local.set(patch);
    } catch (e) { /* ignore */ }
  }

  function applyViewState() {
    root.classList.remove("boxedin-stats--collapsed", "boxedin-stats--maximized");
    if (viewState === "collapsed") root.classList.add("boxedin-stats--collapsed");
    else if (viewState === "maximized") root.classList.add("boxedin-stats--maximized");
  }

  function copyTextToClipboard(text, onDone) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(onDone).catch(function () {
        fallbackCopyText(text, onDone);
      });
      return;
    }
    fallbackCopyText(text, onDone);
  }

  function fallbackCopyText(text, onDone) {
    try {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      if (onDone) onDone();
    } catch (e) { /* ignore */ }
  }

  /* ── Enable page-guard red-team ────────────────────────────────────── */

  function enablePageGuardRedteam() {
    try {
      window.postMessage({ source: "boxedin-overlay", type: "enable-redteam" }, "*");
    } catch (e) { /* ignore */ }
  }

  /* ── Tab management ────────────────────────────────────────────────── */

  function switchTab(tab) {
    activeTab = tab;
    try {
      var patch = {};
      patch[STORAGE_ACTIVE_TAB] = tab;
      chrome.storage.local.set(patch);
    } catch (e) { /* ignore */ }
    renderActivePanel();
  }

  function renderActivePanel() {
    if (activeTab === "blocks") fetchStats();
    else if (activeTab === "auth") fetchAuthAndRender();
    else if (activeTab === "exfil") fetchExfilAndRender();
    else if (activeTab === "inject") fetchInjectAndRender();
  }

  /* ── Wire helpers ──────────────────────────────────────────────────── */

  function wireToggle() {
    var btn = root.querySelector(".boxedin-stats__toggle");
    if (!btn) return;
    btn.addEventListener("click", function () {
      saveViewState(viewState === "collapsed" ? "normal" : "collapsed");
      applyViewState();
      var collapsed = viewState === "collapsed";
      btn.textContent = collapsed ? "\u25B2" : "\u25BC";
      btn.setAttribute("title", collapsed ? "Expand" : "Collapse");
      btn.setAttribute("aria-expanded", collapsed ? "false" : "true");
    });
  }

  function wireMaximize() {
    var btn = root.querySelector(".boxedin-stats__maximize");
    if (!btn) return;
    btn.addEventListener("click", function () {
      saveViewState(viewState === "maximized" ? "normal" : "maximized");
      applyViewState();
      var maximized = viewState === "maximized";
      btn.textContent = maximized ? "\u25A3" : "\u25A1";
      btn.setAttribute("title", maximized ? "Restore" : "Maximize");
    });
  }

  function wireTabs() {
    var tabs = root.querySelectorAll(".boxedin-stats__tab");
    for (var i = 0; i < tabs.length; i++) {
      (function (btn) {
        btn.addEventListener("click", function () {
          var tab = btn.getAttribute("data-tab");
          if (tab && tab !== activeTab) switchTab(tab);
        });
      })(tabs[i]);
    }
  }

  /* ── Render shell (header + tabs + body) ───────────────────────────── */

  function renderShell(bodyHtml, opts) {
    if (!root) return;
    opts = opts || {};
    if (opts.extensionDisabled) {
      root.style.display = "none";
      return;
    }
    root.style.display = "";

    var prevBodyScroll = 0;
    var bodyEl = root.querySelector(".boxedin-stats__body");
    if (bodyEl) prevBodyScroll = bodyEl.scrollTop;

    root.className = "";
    if (isDarkUi()) root.classList.add("boxedin-stats--dark");
    applyViewState();

    var collapsed = root.classList.contains("boxedin-stats--collapsed");
    var maximized = viewState === "maximized";

    var headerActions = "";
    if (activeTab === "blocks") {
      headerActions += '<button type="button" class="boxedin-stats__reset-stats" title="Clear cumulative DNR and page-guard block counts (this browser)">Reset stats</button>';
    }
    headerActions +=
      '<button type="button" class="boxedin-stats__maximize" title="' +
      (maximized ? "Restore" : "Maximize") + '">' +
      (maximized ? "\u25A3" : "\u25A1") + "</button>" +
      '<button type="button" class="boxedin-stats__toggle" title="' +
      (collapsed ? "Expand" : "Collapse") + '" aria-expanded="' +
      (collapsed ? "false" : "true") + '">' +
      (collapsed ? "\u25B2" : "\u25BC") + "</button>";

    var tabsHtml = "";
    if (redteamEnabled) {
      var tabDefs = [
        { id: "blocks", label: "Blocks" },
        { id: "auth", label: "Auth" },
        { id: "exfil", label: "Exfil" },
        { id: "inject", label: "Inject" }
      ];
      tabsHtml = '<div class="boxedin-stats__tabs">';
      for (var t = 0; t < tabDefs.length; t++) {
        var cls = tabDefs[t].id === activeTab ? " boxedin-stats__tab--active" : "";
        tabsHtml += '<button type="button" class="boxedin-stats__tab' + cls +
          '" data-tab="' + tabDefs[t].id + '">' + tabDefs[t].label + '</button>';
      }
      tabsHtml += '</div>';
    }

    root.innerHTML =
      '<div class="boxedin-stats__header">' +
        '<span class="boxedin-stats__title">BoxedIn</span>' +
        '<div class="boxedin-stats__header-actions">' + headerActions + '</div>' +
      '</div>' +
      tabsHtml +
      '<div class="boxedin-stats__body">' + bodyHtml + '</div>';

    wireToggle();
    wireMaximize();
    if (redteamEnabled) wireTabs();

    var newBody = root.querySelector(".boxedin-stats__body");
    if (newBody && prevBodyScroll) newBody.scrollTop = prevBodyScroll;
  }

  /* ── Blocks panel ──────────────────────────────────────────────────── */

  function toggleHostBlock(host, block) {
    try {
      chrome.runtime.sendMessage(
        { type: "BOXEDIN_TOGGLE_HOST_BLOCK", host: host, block: block },
        function () {
          if (chrome.runtime.lastError) return;
          fetchStats();
        }
      );
    } catch (e) { /* ignore */ }
  }

  function enableCaptureHosts() {
    try {
      chrome.runtime.sendMessage(
        { type: "BOXEDIN_SET_CAPTURE_HOSTS", enabled: true },
        function () {
          if (chrome.runtime.lastError) return;
          fetchStats();
        }
      );
    } catch (e) { /* ignore */ }
  }

  function partitionBlockRows(rows) {
    var network = [];
    var sniff = [];
    for (var i = 0; i < rows.length; i++) {
      if (rows[i] && rows[i].kind === "extensionSniff") sniff.push(rows[i]);
      else network.push(rows[i]);
    }
    return { network: network, sniff: sniff };
  }

  function sumRowCounts(arr) {
    var s = 0;
    for (var j = 0; j < arr.length; j++) {
      var c = arr[j] && arr[j].count;
      if (typeof c === "number" && c > 0) s += c;
    }
    return s;
  }

  function buildBlocksBody(payload) {
    if (payload && payload.unavailable) {
      return '<p class="boxedin-stats__hint">' +
        escapeHtml(payload.reason || "Block stats need declarativeNetRequestFeedback in a recent Chrome.") +
        '</p>';
    }

    var rows = (payload && payload.rows) || [];
    var total = (payload && payload.total) || 0;
    var parts = [];

    if (rows.length === 0) {
      parts.push('<p class="boxedin-stats__empty">No requests blocked yet on this profile.</p>');
    } else {
      parts.push('<div class="boxedin-stats__total">Total blocked: <strong>' + total + '</strong></div>');
      var split = partitionBlockRows(rows);

      parts.push(
        '<div class="boxedin-stats__section"><div class="boxedin-stats__section-head">' +
        '<span class="boxedin-stats__section-title">Network &amp; API traffic</span>' +
        '<span class="boxedin-stats__section-sub">' + sumRowCounts(split.network) + '</span></div>');
      if (split.network.length > 0) {
        for (var i = 0; i < split.network.length; i++) {
          var r = split.network[i];
          parts.push(
            '<div class="boxedin-stats__row"><span class="boxedin-stats__label" title="' +
            escapeAttr(r.detail || "") + '">' + escapeHtml(r.label) +
            '</span><span class="boxedin-stats__count">' + r.count + '</span></div>');
        }
      } else {
        parts.push('<p class="boxedin-stats__section-empty">None in this category yet.</p>');
      }
      parts.push('</div>');

      parts.push(
        '<div class="boxedin-stats__section"><div class="boxedin-stats__section-head">' +
        '<span class="boxedin-stats__section-title">Extension sniffing</span>' +
        '<span class="boxedin-stats__section-sub">' + sumRowCounts(split.sniff) + '</span></div>');
      if (split.sniff.length > 0) {
        for (var s = 0; s < split.sniff.length; s++) {
          var sr = split.sniff[s];
          parts.push(
            '<div class="boxedin-stats__row"><span class="boxedin-stats__label" title="' +
            escapeAttr(sr.detail || "") + '">' + escapeHtml(sr.label) +
            '</span><span class="boxedin-stats__count">' + sr.count + '</span></div>');
        }
      } else {
        parts.push(
          '<p class="boxedin-stats__section-empty">' +
          'None yet \u2014 counts DNR rule 2 (chrome-extension://\u2026) and page-guard JS blocks of extension URLs.' +
          '</p>');
      }
      parts.push('</div>');
    }

    var hosts = (payload && payload.observedHosts) || [];
    var blockedHosts = (payload && payload.blockedHosts) || [];
    var blockedSet = {};
    for (var bh = 0; bh < blockedHosts.length; bh++) blockedSet[blockedHosts[bh]] = true;
    var capOn = payload && payload.captureHostsEnabled;

    if (capOn) {
      parts.push(
        '<div class="boxedin-stats__hosts"><div class="boxedin-stats__hosts-head">' +
        '<span class="boxedin-stats__hosts-title">Hostnames (this tab)</span>' +
        '<div class="boxedin-stats__hosts-actions">');
      if (hosts.length > 0) {
        parts.push(
          '<button type="button" class="boxedin-stats__hosts-copy boxedin-stats__hosts-btn" ' +
          'title="Copy all hostnames (one per line)" data-label-copy="Copy all" data-label-copied="Copied">Copy all</button>');
      }
      parts.push(
        '<button type="button" class="boxedin-stats__hosts-reset boxedin-stats__hosts-btn" ' +
        'title="Clear the hostname list for this tab">Reset list</button></div></div>');
      if (hosts.length > 0) {
        parts.push('<p class="boxedin-stats__hosts-hint">Check a hostname to block all sub-resource requests to it.</p>');
        parts.push('<ul class="boxedin-stats__hosts-list">');
        for (var h = 0; h < hosts.length; h++) {
          var isBlocked = !!blockedSet[hosts[h]];
          parts.push(
            '<li class="boxedin-stats__host-item' +
            (isBlocked ? " boxedin-stats__host-item--blocked" : "") + '">' +
            '<label class="boxedin-stats__host-label">' +
            '<input type="checkbox" class="boxedin-stats__host-check" data-host="' +
            escapeAttr(hosts[h]) + '"' + (isBlocked ? " checked" : "") + ' />' +
            '<code>' + escapeHtml(hosts[h]) + '</code></label></li>');
        }
        parts.push('</ul>');
      } else {
        parts.push('<p class="boxedin-stats__hosts-empty">Host capture on \u2014 no hostnames recorded yet in this tab.</p>');
      }
      parts.push('</div>');
    } else {
      parts.push(
        '<div class="boxedin-stats__hosts-off">' +
        '<p class="boxedin-stats__hosts-empty">Hostname capture is off.</p>' +
        '<button type="button" class="boxedin-stats__enable-capture boxedin-stats__hosts-btn">Enable host capture</button>' +
        '</div>');
    }

    return parts.join("");
  }

  function wireBlocksPanel(payload) {
    var hosts = (payload && payload.observedHosts) || [];
    var capOn = payload && payload.captureHostsEnabled;

    var resetBtn = root.querySelector(".boxedin-stats__reset-stats");
    if (resetBtn) {
      resetBtn.addEventListener("click", function () {
        if (pgFlushTimer !== null) {
          clearTimeout(pgFlushTimer);
          pgFlushTimer = null;
        }
        pendingPg.linkedInBlocklist = 0;
        pendingPg.extensionScheme = 0;
        try {
          chrome.runtime.sendMessage({ type: "BOXEDIN_RESET_BLOCK_STATS" }, function () {
            if (chrome.runtime.lastError) return;
            fetchStats();
          });
        } catch (e) { /* ignore */ }
      });
    }

    if (capOn) {
      var hostsResetBtn = root.querySelector(".boxedin-stats__hosts-reset");
      if (hostsResetBtn) {
        hostsResetBtn.addEventListener("click", function () {
          try {
            chrome.runtime.sendMessage({ type: "BOXEDIN_RESET_OBSERVED_HOSTS" }, function () {
              if (chrome.runtime.lastError) return;
              fetchStats();
            });
          } catch (e) { /* ignore */ }
        });
      }

      var checks = root.querySelectorAll(".boxedin-stats__host-check");
      for (var c = 0; c < checks.length; c++) {
        (function (cb) {
          cb.addEventListener("change", function () {
            toggleHostBlock(cb.getAttribute("data-host"), cb.checked);
          });
        })(checks[c]);
      }

      if (hosts.length > 0) {
        var copyBtn = root.querySelector(".boxedin-stats__hosts-copy");
        if (copyBtn) {
          copyBtn.addEventListener("click", function () {
            var text = hosts.join("\n");
            var label = copyBtn.getAttribute("data-label-copy") || "Copy all";
            var labelDone = copyBtn.getAttribute("data-label-copied") || "Copied";
            copyTextToClipboard(text, function () {
              copyBtn.textContent = labelDone;
              setTimeout(function () { copyBtn.textContent = label; }, 1600);
            });
          });
        }
      }
    } else {
      var enableBtn = root.querySelector(".boxedin-stats__enable-capture");
      if (enableBtn) {
        enableBtn.addEventListener("click", function () { enableCaptureHosts(); });
      }
    }
  }

  /* ── Auth panel ────────────────────────────────────────────────────── */

  function buildAuthBody(data) {
    if (!redteamEnabled) {
      return '<p class="boxedin-rt__disabled">Enable red-team tools in the BoxedIn options page.</p>';
    }
    if (!data) return '<p class="boxedin-rt__none">Loading auth audit data\u2026</p>';

    var critical = [];
    var warning = [];
    var info = [];

    var reqHeaders = data.reqHeaders || [];
    for (var ri = 0; ri < reqHeaders.length; ri++) {
      var rh = reqHeaders[ri];
      if (rh.authOverHttp) {
        critical.push("Authorization sent over HTTP: " + escapeHtml((rh.url || "").slice(0, 80)));
      }
      if (rh.tokenType) {
        info.push("Token type: <strong>" + escapeHtml(rh.tokenType) + "</strong> on " +
          escapeHtml((rh.url || "").slice(0, 60)));
      }
    }

    var cookies = data.cookies || [];
    for (var ci = 0; ci < cookies.length; ci++) {
      var ck = cookies[ci];
      if (ck.issues && ck.issues.length > 0) {
        for (var ii = 0; ii < ck.issues.length; ii++) {
          var issue = ck.issues[ii];
          if (ck.isSessionLike && issue.indexOf("HttpOnly") !== -1) {
            critical.push("Cookie <strong>" + escapeHtml(ck.name) + "</strong>: " + escapeHtml(issue));
          } else {
            warning.push("Cookie <strong>" + escapeHtml(ck.name) + "</strong>: " + escapeHtml(issue));
          }
        }
      } else {
        info.push("Cookie: " + escapeHtml(ck.name) + " (" + escapeHtml(ck.domain) + ")" +
          (ck.httpOnly ? " HttpOnly" : "") + (ck.secure ? " Secure" : ""));
      }
    }

    var setCookieIssues = data.setCookieIssues || [];
    for (var sci = 0; sci < setCookieIssues.length; sci++) {
      var scItem = setCookieIssues[sci];
      warning.push("Set-Cookie <strong>" + escapeHtml(scItem.name) + "</strong>: " +
        escapeHtml(scItem.issues.join(", ")));
    }

    var secH = data.securityHeaders || {};
    if (!secH.hsts) warning.push("Missing <strong>Strict-Transport-Security</strong> header");
    if (!secH.xcto) warning.push("Missing <strong>X-Content-Type-Options</strong> header");
    if (!secH.xfo) warning.push("Missing <strong>X-Frame-Options</strong> header");
    if (!secH.hasCsp) warning.push("Missing <strong>Content-Security-Policy</strong> header");
    if (secH.cspReportOnly) warning.push("CSP is <strong>report-only</strong> (not enforced)");

    for (var pga = 0; pga < cachedPageGuardAuth.length; pga++) {
      var pgData = cachedPageGuardAuth[pga];
      if (pgData.findings) {
        for (var fi = 0; fi < pgData.findings.length; fi++) {
          var f = pgData.findings[fi];
          critical.push(escapeHtml(f.issue) + ": <code>" + escapeHtml(f.key) + "</code> = " +
            escapeHtml(f.preview || ""));
        }
      }
    }

    if (critical.length === 0 && warning.length === 0 && info.length === 0) {
      return '<p class="boxedin-rt__none">No auth findings yet. Navigate to a site and reload to scan.</p>';
    }

    var parts = [];

    if (critical.length > 0) {
      parts.push(
        '<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">' +
        '<span class="boxedin-rt__badge boxedin-rt__badge--critical">Critical</span> ' +
        critical.length + ' issue' + (critical.length !== 1 ? 's' : '') + '</div>');
      for (var cr = 0; cr < critical.length; cr++) {
        parts.push('<div class="boxedin-rt__item"><span class="boxedin-rt__item-label">' + critical[cr] + '</span></div>');
      }
      parts.push('</div>');
    }

    if (warning.length > 0) {
      parts.push(
        '<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">' +
        '<span class="boxedin-rt__badge boxedin-rt__badge--warning">Warning</span> ' +
        warning.length + ' issue' + (warning.length !== 1 ? 's' : '') + '</div>');
      for (var w = 0; w < warning.length; w++) {
        parts.push('<div class="boxedin-rt__item"><span class="boxedin-rt__item-label">' + warning[w] + '</span></div>');
      }
      parts.push('</div>');
    }

    if (info.length > 0) {
      parts.push(
        '<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">' +
        '<span class="boxedin-rt__badge boxedin-rt__badge--info">Info</span> ' +
        info.length + ' item' + (info.length !== 1 ? 's' : '') + '</div>');
      for (var inf = 0; inf < info.length; inf++) {
        parts.push('<div class="boxedin-rt__item"><span class="boxedin-rt__item-detail">' + info[inf] + '</span></div>');
      }
      parts.push('</div>');
    }

    return parts.join("");
  }

  function fetchAuthAndRender() {
    try {
      chrome.runtime.sendMessage({ type: "BOXEDIN_GET_AUTH_AUDIT" }, function (response) {
        if (chrome.runtime.lastError) {
          cachedAuthData = null;
          if (activeTab === "auth") renderShell(buildAuthBody(null));
          return;
        }
        cachedAuthData = response;
        if (activeTab === "auth") renderShell(buildAuthBody(response));
      });
    } catch (e) {
      if (activeTab === "auth") renderShell(buildAuthBody(null));
    }
  }

  /* ── Exfil panel ───────────────────────────────────────────────────── */

  function buildExfilBody() {
    if (!redteamEnabled) {
      return '<p class="boxedin-rt__disabled">Enable red-team tools in the BoxedIn options page.</p>';
    }

    var events = cachedExfilEvents;
    var subtypes = ["fetch", "xhr", "clipboard-write", "clipboard-read", "websocket", "form-submit", "large-request"];
    var parts = [];

    parts.push('<div class="boxedin-rt__filters">');
    parts.push('<button type="button" class="boxedin-rt__filter' +
      (exfilFilter === null ? ' boxedin-rt__filter--active' : '') +
      '" data-filter="all">All</button>');
    for (var fi = 0; fi < subtypes.length; fi++) {
      parts.push('<button type="button" class="boxedin-rt__filter' +
        (exfilFilter === subtypes[fi] ? ' boxedin-rt__filter--active' : '') +
        '" data-filter="' + subtypes[fi] + '">' + escapeHtml(subtypes[fi]) + '</button>');
    }
    parts.push('</div>');

    var filtered = [];
    for (var ei = 0; ei < events.length; ei++) {
      if (exfilFilter === null || events[ei].subtype === exfilFilter) {
        filtered.push(events[ei]);
      }
    }

    if (filtered.length === 0) {
      parts.push('<p class="boxedin-rt__none">No exfiltration events captured yet.</p>');
      return parts.join("");
    }

    parts.push('<ul class="boxedin-rt__stream">');
    for (var i = filtered.length - 1; i >= 0; i--) {
      var evt = filtered[i];
      var isThirdParty = false;
      var evtHost = "";
      if (evt.url) {
        try {
          evtHost = new URL(evt.url).hostname;
          var pageHost = window.location.hostname;
          if (evtHost && evtHost !== pageHost && exfilAllowlist.indexOf(evtHost) === -1) {
            isThirdParty = true;
          }
        } catch (e) { /* ignore */ }
      }
      var alertClass = isThirdParty ? " boxedin-rt__event--alert" : "";
      var display = evt.url || evt.preview || evt.action || "\u2014";
      if (evt.bodySize) display += " (" + Math.round(evt.bodySize / 1024) + " KB)";
      parts.push(
        '<li class="boxedin-rt__event' + alertClass + '">' +
        '<span class="boxedin-rt__event-type">' + escapeHtml(evt.subtype || "?") + '</span>' +
        '<span class="boxedin-rt__event-url">' + escapeHtml(display));
      if (isThirdParty && evtHost) {
        parts.push(' <button type="button" class="boxedin-rt__allow-btn" data-host="' +
          escapeAttr(evtHost) + '" title="Add to exfil allowlist">allow</button>');
      }
      parts.push('</span>' +
        '<span class="boxedin-rt__event-ts">' + escapeHtml(formatTime(evt.ts)) + '</span>' +
        '</li>');
    }
    parts.push('</ul>');

    return parts.join("");
  }

  function wireExfilPanel() {
    var filters = root.querySelectorAll(".boxedin-rt__filter");
    for (var i = 0; i < filters.length; i++) {
      (function (btn) {
        btn.addEventListener("click", function () {
          var f = btn.getAttribute("data-filter");
          exfilFilter = f === "all" ? null : f;
          if (activeTab === "exfil") renderActivePanel();
        });
      })(filters[i]);
    }

    var allowBtns = root.querySelectorAll(".boxedin-rt__allow-btn");
    for (var a = 0; a < allowBtns.length; a++) {
      (function (btn) {
        btn.addEventListener("click", function () {
          var host = btn.getAttribute("data-host");
          if (!host) return;
          chrome.storage.local.get([STORAGE_EXFIL_ALLOWLIST], function (items) {
            var list = (items[STORAGE_EXFIL_ALLOWLIST] || []).slice();
            if (list.indexOf(host) === -1) list.push(host);
            var patch = {};
            patch[STORAGE_EXFIL_ALLOWLIST] = list;
            chrome.storage.local.set(patch);
            exfilAllowlist = list;
            if (activeTab === "exfil") renderActivePanel();
          });
        });
      })(allowBtns[a]);
    }
  }

  function fetchExfilAndRender() {
    try {
      chrome.runtime.sendMessage({ type: "BOXEDIN_GET_EXFIL_EVENTS" }, function (response) {
        if (chrome.runtime.lastError) {
          if (activeTab === "exfil") {
            renderShell(buildExfilBody());
            wireExfilPanel();
          }
          return;
        }
        if (response && response.events && response.events.length > cachedExfilEvents.length) {
          cachedExfilEvents = response.events;
        }
        if (activeTab === "exfil") {
          renderShell(buildExfilBody());
          wireExfilPanel();
        }
      });
    } catch (e) {
      if (activeTab === "exfil") {
        renderShell(buildExfilBody());
        wireExfilPanel();
      }
    }
  }

  /* ── Inject panel ──────────────────────────────────────────────────── */

  function buildInjectBody(data) {
    if (!redteamEnabled) {
      return '<p class="boxedin-rt__disabled">Enable red-team tools in the BoxedIn options page.</p>';
    }
    if (!data) return '<p class="boxedin-rt__none">Loading injection findings\u2026</p>';

    var parts = [];

    parts.push('<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">CSP Analysis</div>');
    var csp = data.csp;
    if (csp) {
      if (csp.missing) {
        parts.push(
          '<div class="boxedin-rt__item">' +
          '<span class="boxedin-rt__badge boxedin-rt__badge--critical">Critical</span> ' +
          '<span class="boxedin-rt__item-label">No CSP header present</span></div>');
      } else {
        if (csp.reportOnly) {
          parts.push(
            '<div class="boxedin-rt__item">' +
            '<span class="boxedin-rt__badge boxedin-rt__badge--warning">Warning</span> ' +
            '<span class="boxedin-rt__item-label">CSP is report-only</span></div>');
        }
        if (csp.issues && csp.issues.length > 0) {
          for (var ci = 0; ci < csp.issues.length; ci++) {
            var sev = csp.issues[ci].indexOf("missing") !== -1 ? "warning" : "critical";
            parts.push(
              '<div class="boxedin-rt__item">' +
              '<span class="boxedin-rt__badge boxedin-rt__badge--' + sev + '">' +
              (sev === "critical" ? "Critical" : "Warning") + '</span> ' +
              '<span class="boxedin-rt__item-label">' + escapeHtml(csp.issues[ci]) + '</span></div>');
          }
        }
        if (csp.directives) {
          parts.push('<table class="boxedin-rt__directive-table"><thead><tr><th>Directive</th><th>Value</th></tr></thead><tbody>');
          var dKeys = Object.keys(csp.directives);
          for (var di = 0; di < dKeys.length; di++) {
            parts.push('<tr><td>' + escapeHtml(dKeys[di]) + '</td><td>' +
              escapeHtml(csp.directives[dKeys[di]] || "(empty)") + '</td></tr>');
          }
          parts.push('</tbody></table>');
        }
      }
    } else {
      parts.push('<p class="boxedin-rt__none">No CSP data yet.</p>');
    }
    parts.push('</div>');

    parts.push('<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">CORS Analysis</div>');
    var cors = data.cors || [];
    if (cors.length > 0) {
      for (var coi = 0; coi < cors.length; coi++) {
        parts.push(
          '<div class="boxedin-rt__item">' +
          '<span class="boxedin-rt__badge boxedin-rt__badge--warning">Warning</span> ' +
          '<span class="boxedin-rt__item-label">' + escapeHtml(cors[coi]) + '</span></div>');
      }
    } else {
      parts.push('<p class="boxedin-rt__none">No CORS issues detected.</p>');
    }
    parts.push('</div>');

    parts.push('<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">CSRF Gaps</div>');
    var csrf = data.csrf || [];
    if (csrf.length > 0) {
      for (var csi = 0; csi < csrf.length; csi++) {
        var csrfItem = csrf[csi];
        parts.push(
          '<div class="boxedin-rt__item">' +
          '<span class="boxedin-rt__badge boxedin-rt__badge--warning">Warning</span> ' +
          '<span class="boxedin-rt__item-label">Form without CSRF token</span>' +
          '<div class="boxedin-rt__item-detail">' + escapeHtml(csrfItem.method || "POST") +
          ' \u2192 ' + escapeHtml((csrfItem.action || "").slice(0, 100)) +
          (csrfItem.id ? ' (id="' + escapeHtml(csrfItem.id) + '")' : '') + '</div></div>');
      }
    } else {
      parts.push('<p class="boxedin-rt__none">No CSRF gaps detected (or no forms scanned yet).</p>');
    }
    parts.push('</div>');

    parts.push('<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">XSS Sinks</div>');
    var xss = data.xss || [];
    var reflected = data.reflectedParams || [];
    if (xss.length > 0 || reflected.length > 0) {
      for (var xi = 0; xi < xss.length; xi++) {
        var xssItem = xss[xi];
        parts.push(
          '<div class="boxedin-rt__item">' +
          '<span class="boxedin-rt__badge boxedin-rt__badge--critical">Critical</span> ' +
          '<span class="boxedin-rt__item-label">' + escapeHtml(xssItem.sink || "DOM write") + '</span>' +
          '<div class="boxedin-rt__item-detail">' + escapeHtml(xssItem.preview || "") + '</div></div>');
      }
      for (var rpi = 0; rpi < reflected.length; rpi++) {
        var rp = reflected[rpi];
        parts.push(
          '<div class="boxedin-rt__item">' +
          '<span class="boxedin-rt__badge boxedin-rt__badge--warning">Warning</span> ' +
          '<span class="boxedin-rt__item-label">Reflected ' + escapeHtml(rp.context || "param") +
          ': ' + escapeHtml(rp.param || "") + '</span>' +
          '<div class="boxedin-rt__item-detail">' + escapeHtml((rp.value || "").slice(0, 60)) + '</div></div>');
      }
    } else {
      parts.push('<p class="boxedin-rt__none">No XSS sinks observed yet.</p>');
    }
    parts.push('</div>');

    return parts.join("");
  }

  function fetchInjectAndRender() {
    try {
      chrome.runtime.sendMessage({ type: "BOXEDIN_GET_INJECT_FINDINGS" }, function (response) {
        if (chrome.runtime.lastError) {
          cachedInjectData = null;
          if (activeTab === "inject") renderShell(buildInjectBody(null));
          return;
        }
        cachedInjectData = response;
        if (activeTab === "inject") renderShell(buildInjectBody(response));
      });
    } catch (e) {
      if (activeTab === "inject") renderShell(buildInjectBody(null));
    }
  }

  /* ── Fetch stats (blocks panel) ────────────────────────────────────── */

  function fetchStats() {
    if (pgFlushTimer !== null) {
      clearTimeout(pgFlushTimer);
      pgFlushTimer = null;
    }
    function doGet() {
      try {
        chrome.runtime.sendMessage({ type: "BOXEDIN_GET_BLOCK_STATS" }, function (response) {
          if (chrome.runtime.lastError) {
            cachedBlocksPayload = { unavailable: true, reason: chrome.runtime.lastError.message };
            if (activeTab === "blocks") {
              renderShell(buildBlocksBody(cachedBlocksPayload));
              wireBlocksPanel(cachedBlocksPayload);
            }
            return;
          }
          cachedBlocksPayload = response || { rows: [], total: 0 };
          if (cachedBlocksPayload.extensionDisabled) {
            renderShell("", { extensionDisabled: true });
            return;
          }
          if (activeTab === "blocks") {
            renderShell(buildBlocksBody(cachedBlocksPayload));
            wireBlocksPanel(cachedBlocksPayload);
          }
        });
      } catch (e) {
        cachedBlocksPayload = { unavailable: true, reason: String(e && e.message) };
        if (activeTab === "blocks") {
          renderShell(buildBlocksBody(cachedBlocksPayload));
          wireBlocksPanel(cachedBlocksPayload);
        }
      }
    }
    var li = pendingPg.linkedInBlocklist;
    var es = pendingPg.extensionScheme;
    pendingPg.linkedInBlocklist = 0;
    pendingPg.extensionScheme = 0;
    if (li > 0 || es > 0) {
      var payload = { type: "BOXEDIN_PAGE_GUARD_STAT" };
      if (li > 0) payload.linkedInBlocklist = li;
      if (es > 0) payload.extensionScheme = es;
      try {
        chrome.runtime.sendMessage(payload, function () {
          if (chrome.runtime.lastError) { /* ignore */ }
          doGet();
        });
      } catch (e2) {
        pendingPg.linkedInBlocklist += li;
        pendingPg.extensionScheme += es;
        doGet();
      }
    } else {
      doGet();
    }
  }

  /* ── Mount ─────────────────────────────────────────────────────────── */

  function mount() {
    if (document.getElementById("boxedin-block-stats-root")) return;
    root = document.createElement("div");
    root.id = "boxedin-block-stats-root";
    root.setAttribute("role", "complementary");
    root.setAttribute("aria-label", "BoxedIn network block statistics");
    (document.body || document.documentElement).appendChild(root);

    chrome.storage.onChanged.addListener(function (changes, areaName) {
      if (areaName !== "local") return;
      if (changes.extensionEnabled) {
        if (changes.extensionEnabled.newValue === false) {
          root.style.display = "none";
        } else {
          renderActivePanel();
        }
      }
      if (changes.pageGuardBlockStats || changes.blockStatsByRuleId ||
          changes.captureRequestHostsEnabled || changes.blockedHosts) {
        if (activeTab === "blocks") fetchStats();
      }
      if (changes[STORAGE_REDTEAM_ENABLED]) {
        redteamEnabled = !!changes[STORAGE_REDTEAM_ENABLED].newValue;
        if (redteamEnabled) {
          enablePageGuardRedteam();
        } else {
          activeTab = "blocks";
        }
        renderActivePanel();
      }
      if (changes[STORAGE_EXFIL_ALLOWLIST]) {
        exfilAllowlist = changes[STORAGE_EXFIL_ALLOWLIST].newValue || [];
      }
    });

    var storageKeys = {};
    storageKeys[STORAGE_VIEW_STATE] = "normal";
    storageKeys[STORAGE_ACTIVE_TAB] = "blocks";
    storageKeys[STORAGE_REDTEAM_ENABLED] = false;
    storageKeys[STORAGE_EXFIL_ALLOWLIST] = [];
    chrome.storage.local.get(storageKeys, function (items) {
      var saved = items[STORAGE_VIEW_STATE];
      if (saved === "collapsed" || saved === "maximized") viewState = saved;

      redteamEnabled = !!items[STORAGE_REDTEAM_ENABLED];
      exfilAllowlist = items[STORAGE_EXFIL_ALLOWLIST] || [];

      if (redteamEnabled) {
        var savedTab = items[STORAGE_ACTIVE_TAB];
        if (savedTab === "auth" || savedTab === "exfil" || savedTab === "inject") {
          activeTab = savedTab;
        }
        enablePageGuardRedteam();
      }

      applyViewState();
      renderActivePanel();
    });

    window.setInterval(function () { renderActivePanel(); }, POLL_MS);
  }

  if (document.body) {
    mount();
  } else {
    document.addEventListener("DOMContentLoaded", mount);
  }
})();
