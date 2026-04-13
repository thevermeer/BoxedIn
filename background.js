/**
 * Service worker: DNR (bundled + user), block stats, page-guard registration,
 * optional hostname capture (webRequest), extension enable/disable.
 *
 * DNR id ranges (must not overlap; see rules-ids.txt):
 * - Bundled static: rules.json, ids 1–9999 (currently 1–8).
 * - User dynamic: USER_RULE_ID_BASE .. USER_RULE_ID_BASE + MAX_USER_RULES - 1
 *   (10000–10049).
 * - Per-host blocking (overlay checkboxes): HOST_BLOCK_RULE_ID_BASE ..
 *   HOST_BLOCK_RULE_ID_BASE + MAX_HOST_BLOCK_RULES - 1 (20000–20499).
 */
(function () {
  "use strict";

  var STORAGE_KEY = "userDnrUrlFilters";
  /** Start of dynamic rule ids; must stay below 100000 and clear of bundled 1–9999. */
  var USER_RULE_ID_BASE = 10000;
  var MAX_USER_RULES = 50;
  var STORAGE_LAST_ERROR = "userDnrLastApplyError";
  var STORAGE_LAST_AT = "userDnrLastApplyAt";
  var STORAGE_BLOCK_STATS = "blockStatsByRuleId";
  /** Page-guard (MAIN world) JS-layer blocks; linkedInBlocklist + extensionScheme */
  var STORAGE_PAGE_GUARD = "pageGuardBlockStats";
  /** Opt-in: record unique request hostnames per tab via webRequest (not full URLs). */
  var STORAGE_CAPTURE_HOSTS = "captureRequestHostsEnabled";
  /** Global master switch: DNR + page-guard registration + overlay stats. */
  var STORAGE_EXTENSION_ENABLED = "extensionEnabled";
  /** Hostnames the user has chosen to block via the overlay checkboxes. */
  var STORAGE_BLOCKED_HOSTS = "blockedHosts";
  /** Start of dynamic rule ids for per-host blocking; clear of user 10000–10049. */
  var HOST_BLOCK_RULE_ID_BASE = 20000;
  var MAX_HOST_BLOCK_RULES = 500;
  /** Dynamic MAIN-world page-guard (see manifest; not static content_scripts). */
  var PAGE_GUARD_SCRIPT_ID = "boxedin-page-guard";

  var STORAGE_REDTEAM_ENABLED = "redteamEnabled";
  var STORAGE_EXFIL_ALLOWLIST = "redteamExfilAllowlist";
  var STORAGE_BLOCKED_COOKIES = "blockedCookies";
  var redteamEnabled = false;
  var blockedCookiesList = [];
  var headerFindingsByTab = new Map();
  var exfilEventsByTab = new Map();
  var injectFindingsByTab = new Map();
  var techFindingsByTab = new Map();
  var MAX_TECH_FINDINGS_PER_TAB = 100;
  var apiFindingsByTab = new Map();
  var MAX_API_FINDINGS_PER_TAB = 200;
  var depsFindingsByTab = new Map();
  var MAX_DEPS_FINDINGS_PER_TAB = 200;
  var timelineEventsByTab = new Map();
  var MAX_TIMELINE_EVENTS_PER_TAB = 500;
  var MAX_EXFIL_EVENTS_PER_TAB = 200;
  var MAX_HEADER_FINDINGS_PER_TAB = 100;

  /** tabId -> array of captured request objects for the repeater. */
  var capturedRequestsByTab = new Map();
  /** requestId -> partial body/method data awaiting headers from onBeforeSendHeaders. */
  var pendingBodiesByRequestId = new Map();
  var MAX_CAPTURED_REQUESTS_PER_TAB = 100;
  var MAX_PENDING_BODIES = 500;

  /** tabId -> Set of hostname strings (cleared when service worker restarts). */
  var observedHostsByTab = new Map();
  var MAX_UNIQUE_HOSTS_PER_TAB = 500;
  var captureHostsEnabled = false;
  var extensionEnabled = true;

  /** Short labels for bundled rules (ids must match rules.json). */
  var BUNDLED_RULE_META = {
    1: {
      label: "sensorCollect",
      detail: "*linkedin.com/sensorCollect*",
    },
    2: {
      label: "Extension probe",
      detail: "*chrome-extension://invalid*",
    },
    3: {
      label: "li/track",
      detail: "*linkedin.com/li/track*",
    },
    4: {
      label: "Protechts collector",
      detail: "*collector-pxdojv695v.protechts.net*",
    },
    5: {
      label: "Realtime connectivity",
      detail: "*realtimeFrontendClientConnectivityTracking*",
    },
    6: {
      label: "tscp-serving",
      detail: "*linkedin.com/tscp-serving*",
    },
    7: {
      label: "cs.ns1p.net",
      detail: "*cs.ns1p.net*",
    },
    8: {
      label: "li/tscp/sct",
      detail: "*linkedin.com/li/tscp/sct*",
    },
  };

  var RESOURCE_TYPES = [
    "xmlhttprequest",
    "ping",
    "csp_report",
    "script",
    "image",
    "sub_frame",
    "stylesheet",
    "media",
    "other",
  ];

  var memPendingBumps = {};
  var flushStatsTimer = null;

  /** Prevents concurrent updateDynamicRules (duplicate rule id errors). */
  var applyDnrInFlight = false;
  var applyDnrQueued = false;
  var scheduleDnrTimer = null;

  function flushBlockStats() {
    flushStatsTimer = null;
    var bumps = memPendingBumps;
    memPendingBumps = {};
    var keys = Object.keys(bumps);
    if (keys.length === 0) return;
    chrome.storage.local.get(
      (function () {
        var d = {};
        d[STORAGE_BLOCK_STATS] = {};
        return d;
      })(),
      function (items) {
        var c = items[STORAGE_BLOCK_STATS] || {};
        var i = 0;
        for (; i < keys.length; i++) {
          var k = keys[i];
          c[k] = (c[k] || 0) + bumps[k];
        }
        var patch = {};
        patch[STORAGE_BLOCK_STATS] = c;
        chrome.storage.local.set(patch);
      }
    );
  }

  function resetAllBlockStats() {
    if (flushStatsTimer !== null) {
      clearTimeout(flushStatsTimer);
      flushStatsTimer = null;
    }
    memPendingBumps = {};
    var patch = {};
    patch[STORAGE_BLOCK_STATS] = {};
    patch[STORAGE_PAGE_GUARD] = { linkedInBlocklist: 0, extensionScheme: 0 };
    chrome.storage.local.set(patch);
  }

  function bumpRuleCount(ruleId) {
    if (ruleId == null || ruleId !== ruleId) return;
    var k = String(ruleId);
    memPendingBumps[k] = (memPendingBumps[k] || 0) + 1;
    if (flushStatsTimer !== null) {
      clearTimeout(flushStatsTimer);
    }
    flushStatsTimer = setTimeout(flushBlockStats, 400);
  }

  function getMatchedRuleId(info) {
    if (!info) return null;
    if (info.rule && typeof info.rule.id === "number") return info.rule.id;
    if (typeof info.ruleId === "number") return info.ruleId;
    return null;
  }

  if (
    chrome.declarativeNetRequest &&
    chrome.declarativeNetRequest.onRuleMatched
  ) {
    try {
      chrome.declarativeNetRequest.onRuleMatched.addListener(function (info) {
        var rid = getMatchedRuleId(info);
        if (rid != null) bumpRuleCount(rid);
      });
    } catch (e) {
      console.warn("[BoxedIn] onRuleMatched:", e);
    }
  }

  function normalizeFilters(raw) {
    if (!Array.isArray(raw)) return [];
    var out = [];
    var seen = {};
    var i = 0;
    for (; i < raw.length && out.length < MAX_USER_RULES; i++) {
      var s = String(raw[i] == null ? "" : raw[i]).trim();
      if (!s) continue;
      if (seen[s]) continue;
      seen[s] = true;
      out.push(s);
    }
    return out;
  }

  function buildRules(filters) {
    var rules = [];
    var i = 0;
    for (; i < filters.length; i++) {
      rules.push({
        id: USER_RULE_ID_BASE + i,
        priority: 1,
        action: { type: "block" },
        condition: {
          urlFilter: filters[i],
          resourceTypes: RESOURCE_TYPES.slice(),
        },
      });
    }
    return rules;
  }

  function finishApplyDnr() {
    applyDnrInFlight = false;
    if (applyDnrQueued) {
      applyDnrQueued = false;
      applyUserDnrRulesNow();
    }
  }

  /**
   * Coalesces rapid storage updates; still serialized via applyDnrInFlight.
   */
  function scheduleApplyUserDnrRules() {
    if (scheduleDnrTimer !== null) {
      clearTimeout(scheduleDnrTimer);
    }
    scheduleDnrTimer = setTimeout(function () {
      scheduleDnrTimer = null;
      applyUserDnrRulesNow();
    }, 80);
  }

  function removeUserDynamicRules(done) {
    chrome.declarativeNetRequest.getDynamicRules(function (existing) {
      try {
        var removeIds = [];
        var seenRemove = {};
        var e = 0;
        for (; e < existing.length; e++) {
          var id = existing[e].id;
          if (
            id >= USER_RULE_ID_BASE &&
            id < USER_RULE_ID_BASE + MAX_USER_RULES
          ) {
            if (!seenRemove[id]) {
              seenRemove[id] = true;
              removeIds.push(id);
            }
          }
        }
        if (removeIds.length === 0) {
          if (done) done();
          return;
        }
        chrome.declarativeNetRequest.updateDynamicRules(
          { removeRuleIds: removeIds, addRules: [] },
          function () {
            if (chrome.runtime.lastError) {
              console.error(
                "[BoxedIn] clear user DNR rules:",
                chrome.runtime.lastError.message
              );
            }
            if (done) done();
          }
        );
      } catch (eRm) {
        console.error("[BoxedIn] removeUserDynamicRules:", eRm);
        if (done) done();
      }
    });
  }

  function updateActionUi() {
    if (!chrome.action) return;
    try {
      chrome.action.setBadgeText({
        text: extensionEnabled ? "" : "OFF",
      });
      chrome.action.setBadgeBackgroundColor({ color: "#9a1c1c" });
      chrome.action.setTitle({
        title: extensionEnabled ? "BoxedIn" : "BoxedIn (disabled)",
      });
    } catch (eUi) {
      console.warn("[BoxedIn] updateActionUi:", eUi);
    }
  }

  /** Toolbar context menu label (id boxedin-toggle). Ignores missing menu. */
  function updateToggleMenuTitle() {
    chrome.contextMenus.update(
      "boxedin-toggle",
      {
        title: extensionEnabled ? "Disable BoxedIn" : "Enable BoxedIn",
      },
      function () {
        if (chrome.runtime.lastError) {
          /* Menu may not exist yet (first paint). */
        }
      }
    );
  }

  function ensurePageGuardScript(enabled) {
    if (!chrome.scripting || !chrome.scripting.registerContentScripts) return;
    if (enabled) {
      chrome.scripting.getRegisteredContentScripts(
        { ids: [PAGE_GUARD_SCRIPT_ID] },
        function (scripts) {
          if (chrome.runtime.lastError) {
            console.warn(
              "[BoxedIn] getRegisteredContentScripts:",
              chrome.runtime.lastError.message
            );
            return;
          }
          if (scripts && scripts.length) return;
          chrome.scripting.registerContentScripts(
            [
              {
                id: PAGE_GUARD_SCRIPT_ID,
                matches: ["<all_urls>"],
                js: ["page-guard.js"],
                runAt: "document_start",
                world: "MAIN",
                allFrames: true,
              },
            ],
            function () {
              if (chrome.runtime.lastError) {
                console.warn(
                  "[BoxedIn] registerContentScripts:",
                  chrome.runtime.lastError.message
                );
              }
            }
          );
        }
      );
    } else {
      chrome.scripting.unregisterContentScripts(
        { ids: [PAGE_GUARD_SCRIPT_ID] },
        function () {
          if (chrome.runtime.lastError) {
            console.warn(
              "[BoxedIn] unregisterContentScripts:",
              chrome.runtime.lastError.message
            );
          }
        }
      );
    }
  }

  function applyExtensionEnabledState(enabled) {
    extensionEnabled = !!enabled;
    var dnr = chrome.declarativeNetRequest;
    if (!dnr || !dnr.updateEnabledRulesets) {
      scheduleApplyUserDnrRules();
      scheduleApplyHostBlockRules();
      ensurePageGuardScript(extensionEnabled);
      updateActionUi();
      updateToggleMenuTitle();
      return;
    }
    dnr.updateEnabledRulesets(
      extensionEnabled
        ? { enableRulesetIds: ["ruleset_1"] }
        : { disableRulesetIds: ["ruleset_1"] },
      function () {
        if (chrome.runtime.lastError) {
          console.warn(
            "[BoxedIn] updateEnabledRulesets:",
            chrome.runtime.lastError.message
          );
        }
        scheduleApplyUserDnrRules();
        scheduleApplyHostBlockRules();
        ensurePageGuardScript(extensionEnabled);
        updateActionUi();
        updateToggleMenuTitle();
      }
    );
  }

  function initFromStorage() {
    chrome.storage.local.get(
      (function () {
        var d = {};
        d[STORAGE_CAPTURE_HOSTS] = false;
        d[STORAGE_EXTENSION_ENABLED] = true;
        d[STORAGE_REDTEAM_ENABLED] = false;
        d[STORAGE_BLOCKED_COOKIES] = [];
        return d;
      })(),
      function (items) {
        captureHostsEnabled = !!items[STORAGE_CAPTURE_HOSTS];
        extensionEnabled = items[STORAGE_EXTENSION_ENABLED] !== false;
        redteamEnabled = !!items[STORAGE_REDTEAM_ENABLED];
        blockedCookiesList = Array.isArray(items[STORAGE_BLOCKED_COOKIES]) ? items[STORAGE_BLOCKED_COOKIES] : [];
        chrome.contextMenus.removeAll(function () {
          chrome.contextMenus.create(
            {
              id: "boxedin-toggle",
              title: extensionEnabled
                ? "Disable BoxedIn"
                : "Enable BoxedIn",
              contexts: ["action"],
            },
            function () {
              if (chrome.runtime.lastError) {
                console.warn(
                  "[BoxedIn] contextMenus.create:",
                  chrome.runtime.lastError.message
                );
              }
              applyExtensionEnabledState(extensionEnabled);
            }
          );
        });
      }
    );
  }

  function applyUserDnrRulesNow() {
    if (applyDnrInFlight) {
      applyDnrQueued = true;
      return;
    }
    if (!extensionEnabled) {
      applyDnrInFlight = true;
      removeUserDynamicRules(finishApplyDnr);
      return;
    }
    applyDnrInFlight = true;
    chrome.storage.local.get(
      (function () {
        var d = {};
        d[STORAGE_KEY] = [];
        return d;
      })(),
      function (result) {
        try {
          var filters = normalizeFilters(result[STORAGE_KEY]);
          chrome.declarativeNetRequest.getDynamicRules(function (existing) {
            try {
              var removeIds = [];
              var seenRemove = {};
              var e = 0;
              for (; e < existing.length; e++) {
                var id = existing[e].id;
                if (
                  id >= USER_RULE_ID_BASE &&
                  id < USER_RULE_ID_BASE + MAX_USER_RULES
                ) {
                  if (!seenRemove[id]) {
                    seenRemove[id] = true;
                    removeIds.push(id);
                  }
                }
              }
              var addRules = buildRules(filters);
              chrome.declarativeNetRequest.updateDynamicRules(
                { removeRuleIds: removeIds, addRules: addRules },
                function () {
                  if (chrome.runtime.lastError) {
                    var msg = chrome.runtime.lastError.message;
                    console.error("[BoxedIn] user DNR rules:", msg);
                    var errPatch = {};
                    errPatch[STORAGE_LAST_ERROR] = msg;
                    errPatch[STORAGE_LAST_AT] = Date.now();
                    chrome.storage.local.set(errPatch);
                  } else {
                    var okPatch = {};
                    okPatch[STORAGE_LAST_ERROR] = "";
                    okPatch[STORAGE_LAST_AT] = Date.now();
                    chrome.storage.local.set(okPatch);
                  }
                  finishApplyDnr();
                }
              );
            } catch (eApply) {
              console.error("[BoxedIn] apply DNR (getDynamicRules):", eApply);
              finishApplyDnr();
            }
          });
        } catch (eGet) {
          console.error("[BoxedIn] apply DNR (storage):", eGet);
          finishApplyDnr();
        }
      }
    );
  }

  /* ── Per-hostname blocking (overlay checkboxes) ─────────────────────── */

  var applyHostDnrInFlight = false;
  var applyHostDnrQueued = false;
  var scheduleHostDnrTimer = null;

  function finishApplyHostDnr() {
    applyHostDnrInFlight = false;
    if (applyHostDnrQueued) {
      applyHostDnrQueued = false;
      applyHostBlockRulesNow();
    }
  }

  function scheduleApplyHostBlockRules() {
    if (scheduleHostDnrTimer !== null) {
      clearTimeout(scheduleHostDnrTimer);
    }
    scheduleHostDnrTimer = setTimeout(function () {
      scheduleHostDnrTimer = null;
      applyHostBlockRulesNow();
    }, 80);
  }

  function removeHostBlockRules(done) {
    chrome.declarativeNetRequest.getDynamicRules(function (existing) {
      try {
        var removeIds = [];
        var e = 0;
        for (; e < existing.length; e++) {
          var id = existing[e].id;
          if (
            id >= HOST_BLOCK_RULE_ID_BASE &&
            id < HOST_BLOCK_RULE_ID_BASE + MAX_HOST_BLOCK_RULES
          ) {
            removeIds.push(id);
          }
        }
        if (removeIds.length === 0) {
          if (done) done();
          return;
        }
        chrome.declarativeNetRequest.updateDynamicRules(
          { removeRuleIds: removeIds, addRules: [] },
          function () {
            if (chrome.runtime.lastError) {
              console.error(
                "[BoxedIn] clear host block rules:",
                chrome.runtime.lastError.message
              );
            }
            if (done) done();
          }
        );
      } catch (eRm) {
        console.error("[BoxedIn] removeHostBlockRules:", eRm);
        if (done) done();
      }
    });
  }

  function applyHostBlockRulesNow() {
    if (applyHostDnrInFlight) {
      applyHostDnrQueued = true;
      return;
    }
    if (!extensionEnabled) {
      applyHostDnrInFlight = true;
      removeHostBlockRules(finishApplyHostDnr);
      return;
    }
    applyHostDnrInFlight = true;
    chrome.storage.local.get(
      (function () {
        var d = {};
        d[STORAGE_BLOCKED_HOSTS] = [];
        return d;
      })(),
      function (items) {
        try {
          var hosts = items[STORAGE_BLOCKED_HOSTS] || [];
          chrome.declarativeNetRequest.getDynamicRules(function (existing) {
            try {
              var removeIds = [];
              var e = 0;
              for (; e < existing.length; e++) {
                var id = existing[e].id;
                if (
                  id >= HOST_BLOCK_RULE_ID_BASE &&
                  id < HOST_BLOCK_RULE_ID_BASE + MAX_HOST_BLOCK_RULES
                ) {
                  removeIds.push(id);
                }
              }
              var addRules = [];
              var i = 0;
              for (; i < hosts.length && i < MAX_HOST_BLOCK_RULES; i++) {
                addRules.push({
                  id: HOST_BLOCK_RULE_ID_BASE + i,
                  priority: 1,
                  action: { type: "block" },
                  condition: {
                    requestDomains: [hosts[i]],
                    resourceTypes: RESOURCE_TYPES.slice(),
                  },
                });
              }
              chrome.declarativeNetRequest.updateDynamicRules(
                { removeRuleIds: removeIds, addRules: addRules },
                function () {
                  if (chrome.runtime.lastError) {
                    console.error(
                      "[BoxedIn] host block rules:",
                      chrome.runtime.lastError.message
                    );
                  }
                  finishApplyHostDnr();
                }
              );
            } catch (eApply) {
              console.error("[BoxedIn] applyHostBlockRules:", eApply);
              finishApplyHostDnr();
            }
          });
        } catch (eGet) {
          console.error("[BoxedIn] applyHostBlockRules (storage):", eGet);
          finishApplyHostDnr();
        }
      }
    );
  }

  /* ── Stats / payload ───────────────────────────────────────────────── */

  function mergeCountsWithPending(stored) {
    var c = {};
    var k;
    for (k in stored) {
      if (Object.prototype.hasOwnProperty.call(stored, k)) {
        c[k] = stored[k];
      }
    }
    for (k in memPendingBumps) {
      if (Object.prototype.hasOwnProperty.call(memPendingBumps, k)) {
        c[k] = (c[k] || 0) + memPendingBumps[k];
      }
    }
    return c;
  }

  /** Builds overlay JSON: DNR rows, page-guard rows, optional observed hosts. */
  function buildStatsPayload(sendResponse, sender) {
    if (!extensionEnabled) {
      sendResponse({
        extensionDisabled: true,
        rows: [],
        total: 0,
        captureHostsEnabled: false,
        observedHosts: [],
      });
      return;
    }
    chrome.storage.local.get(
      (function () {
        var d = {};
        d[STORAGE_BLOCK_STATS] = {};
        d[STORAGE_PAGE_GUARD] = { linkedInBlocklist: 0, extensionScheme: 0 };
        d[STORAGE_BLOCKED_HOSTS] = [];
        return d;
      })(),
      function (items) {
        var stored = items[STORAGE_BLOCK_STATS] || {};
        var pgStored = items[STORAGE_PAGE_GUARD] || {};
        var blockedHosts = items[STORAGE_BLOCKED_HOSTS] || [];
        var counts = mergeCountsWithPending(stored);
        chrome.declarativeNetRequest.getDynamicRules(function (dyn) {
          var dynFilterById = {};
          var d = 0;
          for (; d < dyn.length; d++) {
            var dr = dyn[d];
            if (dr && dr.condition && typeof dr.id === "number") {
              if (dr.condition.urlFilter) {
                dynFilterById[dr.id] = dr.condition.urlFilter;
              } else if (
                dr.condition.requestDomains &&
                dr.condition.requestDomains.length > 0
              ) {
                dynFilterById[dr.id] =
                  "host:" + dr.condition.requestDomains[0];
              }
            }
          }
          var rows = [];
          var total = 0;
          var keys = Object.keys(counts);
          keys.sort(function (a, b) {
            return Number(a) - Number(b);
          });
          var i = 0;
          for (; i < keys.length; i++) {
            var idStr = keys[i];
            var n = counts[idStr];
            if (!n || n <= 0) continue;
            var id = Number(idStr);
            total += n;
            var meta = BUNDLED_RULE_META[id];
            var label;
            var detail;
            if (meta) {
              label = meta.label;
              detail = meta.detail;
            } else if (dynFilterById[id]) {
              var uf = dynFilterById[id];
              label =
                uf.length > 36 ? uf.slice(0, 34) + "…" : uf;
              detail = uf;
            } else {
              label = "Rule " + id;
              detail = "id " + id;
            }
            rows.push({
              label: label,
              detail: detail,
              count: n,
              ruleId: id,
              kind: id === 2 ? "extensionSniff" : "network",
            });
          }
          var pgLi = pgStored.linkedInBlocklist || 0;
          if (pgLi > 0) {
            total += pgLi;
            rows.push({
              label: "LinkedIn / telemetry URLs (page-guard JS)",
              detail:
                "Patched fetch, XMLHttpRequest, and sendBeacon for blocklisted HTTP(S) URLs (JS layer; complements DNR).",
              count: pgLi,
              source: "pageGuard",
              kind: "network",
            });
          }
          var pgExt = pgStored.extensionScheme || 0;
          if (pgExt > 0) {
            total += pgExt;
            rows.push({
              label: "chrome-extension://… (extension-guard JS)",
              detail:
                "extension-probe-guard: blocked chrome-extension:// requests (fetch, XHR, src/href, DOM insertion, setAttribute). Independent of DNR rule 2.",
              count: pgExt,
              source: "pageGuard",
              kind: "extensionSniff",
            });
          }
          var payload = { rows: rows, total: total, blockedHosts: blockedHosts };
          attachObservedHostsForOverlay(payload, sender);
          sendResponse(payload);
        });
      }
    );
  }

  function attachObservedHostsForOverlay(payload, sender) {
    payload.captureHostsEnabled = captureHostsEnabled;
    var tid =
      sender && sender.tab && typeof sender.tab.id === "number"
        ? sender.tab.id
        : -1;
    if (!captureHostsEnabled || tid < 0) {
      payload.observedHosts = [];
      return;
    }
    var set = observedHostsByTab.get(tid);
    payload.observedHosts = set ? Array.from(set).sort() : [];
  }

  /** Merges overlay-reported page-guard deltas into pageGuardBlockStats. */
  function applyPageGuardStatMessage(msg) {
    var li = 0;
    var es = 0;
    if (typeof msg.linkedInBlocklist === "number" && msg.linkedInBlocklist > 0) {
      li = Math.floor(msg.linkedInBlocklist);
    }
    if (typeof msg.extensionScheme === "number" && msg.extensionScheme > 0) {
      es = Math.floor(msg.extensionScheme);
    }
    if (typeof msg.delta === "number" && msg.delta > 0) {
      if (msg.key === "extensionScheme") {
        es += Math.floor(msg.delta);
      } else {
        li += Math.floor(msg.delta);
      }
    }
    if (li === 0 && es === 0) {
      return;
    }
    chrome.storage.local.get(
      (function () {
        var o = {};
        o[STORAGE_PAGE_GUARD] = { linkedInBlocklist: 0, extensionScheme: 0 };
        return o;
      })(),
      function (items) {
        var pg = items[STORAGE_PAGE_GUARD] || {};
        if (li > 0) {
          pg.linkedInBlocklist = (pg.linkedInBlocklist || 0) + li;
        }
        if (es > 0) {
          pg.extensionScheme = (pg.extensionScheme || 0) + es;
        }
        var patch = {};
        patch[STORAGE_PAGE_GUARD] = pg;
        chrome.storage.local.set(patch);
      }
    );
  }

  chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
    if (msg && msg.type === "BOXEDIN_OPEN_TAB") {
      var tabUrl = msg.url || "";
      if (tabUrl.indexOf("https://") === 0) {
        chrome.tabs.create({ url: tabUrl });
      }
      sendResponse({ ok: true });
      return true;
    }
    if (msg && msg.type === "BOXEDIN_PAGE_GUARD_STAT") {
      applyPageGuardStatMessage(msg);
      sendResponse({ ok: true });
      return true;
    }
    if (msg && msg.type === "BOXEDIN_GET_BLOCK_STATS") {
      buildStatsPayload(sendResponse, sender);
      return true;
    }
    if (msg && msg.type === "BOXEDIN_RESET_OBSERVED_HOSTS") {
      var tid =
        sender && sender.tab && typeof sender.tab.id === "number"
          ? sender.tab.id
          : -1;
      if (tid >= 0) {
        observedHostsByTab.delete(tid);
      }
      sendResponse({ ok: true });
      return true;
    }
    if (msg && msg.type === "BOXEDIN_RESET_BLOCK_STATS") {
      resetAllBlockStats();
      sendResponse({ ok: true });
      return true;
    }
    if (msg && msg.type === "BOXEDIN_TOGGLE_HOST_BLOCK") {
      var tHost = String(msg.host || "").toLowerCase().trim();
      var tBlock = !!msg.block;
      if (!tHost) {
        sendResponse({ ok: false });
        return true;
      }
      chrome.storage.local.get(
        (function () {
          var d = {};
          d[STORAGE_BLOCKED_HOSTS] = [];
          return d;
        })(),
        function (items) {
          var hosts = items[STORAGE_BLOCKED_HOSTS] || [];
          var idx = hosts.indexOf(tHost);
          if (tBlock && idx === -1) {
            hosts.push(tHost);
          } else if (!tBlock && idx !== -1) {
            hosts.splice(idx, 1);
          }
          var patch = {};
          patch[STORAGE_BLOCKED_HOSTS] = hosts;
          chrome.storage.local.set(patch);
          sendResponse({ ok: true });
        }
      );
      return true;
    }
    if (msg && msg.type === "BOXEDIN_SET_CAPTURE_HOSTS") {
      var patch = {};
      patch[STORAGE_CAPTURE_HOSTS] = !!msg.enabled;
      chrome.storage.local.set(patch);
      sendResponse({ ok: true });
      return true;
    }
    if (msg && msg.type === "BOXEDIN_REMOVE_COOKIE") {
      var ckUrl = msg.url || "";
      var ckName = msg.name || "";
      var ckDomain = msg.domain || "";
      if (chrome.cookies && chrome.cookies.remove && ckUrl && ckName) {
        chrome.cookies.remove({ url: ckUrl, name: ckName }, function () {
          var wasRemoved = !chrome.runtime.lastError;
          if (wasRemoved && ckName && ckDomain) {
            var alreadyBlocked = false;
            for (var bi = 0; bi < blockedCookiesList.length; bi++) {
              if (blockedCookiesList[bi].name === ckName && blockedCookiesList[bi].domain === ckDomain) {
                alreadyBlocked = true;
                break;
              }
            }
            if (!alreadyBlocked) {
              blockedCookiesList.push({ name: ckName, domain: ckDomain });
              var patch = {};
              patch[STORAGE_BLOCKED_COOKIES] = blockedCookiesList;
              chrome.storage.local.set(patch);
            }
          }
          sendResponse({ ok: true, removed: wasRemoved });
        });
      } else {
        sendResponse({ ok: false });
      }
      return true;
    }
    if (msg && msg.type === "BOXEDIN_UNBLOCK_COOKIE") {
      var ubName = msg.name || "";
      var ubDomain = msg.domain || "";
      if (ubName && ubDomain) {
        blockedCookiesList = blockedCookiesList.filter(function (e) {
          return !(e.name === ubName && e.domain === ubDomain);
        });
        var ubPatch = {};
        ubPatch[STORAGE_BLOCKED_COOKIES] = blockedCookiesList;
        chrome.storage.local.set(ubPatch);
      }
      sendResponse({ ok: true });
      return true;
    }
    if (msg && msg.type === "BOXEDIN_GET_AUTH_AUDIT") {
      var authTid = sender && sender.tab && typeof sender.tab.id === "number" ? sender.tab.id : -1;
      var authUrl = sender && sender.tab ? sender.tab.url : "";
      var hf = headerFindingsByTab.get(authTid) || { reqHeaders: [], respHeaders: [], securityHeaders: {}, setCookieIssues: [] };
      if (chrome.cookies && chrome.cookies.getAll && authUrl) {
        chrome.cookies.getAll({ url: authUrl }, function (cookies) {
          var cookieAudit = [];
          for (var ci = 0; ci < cookies.length; ci++) {
            var ck = cookies[ci];
            var isSession = /session|token|auth|sid|jwt/i.test(ck.name);
            var issues = [];
            if (isSession && !ck.httpOnly) issues.push("missing HttpOnly");
            if (!ck.secure) issues.push("missing Secure");
            if (ck.sameSite === "no_restriction" && !ck.secure) issues.push("SameSite=None without Secure");
            if (isSession && ck.expirationDate) {
              var daysToExpiry = (ck.expirationDate - Date.now() / 1000) / 86400;
              if (daysToExpiry > 30) issues.push("excessive expiry (" + Math.round(daysToExpiry) + " days)");
            }
            var ckProto = ck.secure ? "https://" : "http://";
            var ckDom = ck.domain.charAt(0) === "." ? ck.domain.slice(1) : ck.domain;
            cookieAudit.push({
              name: ck.name,
              domain: ck.domain,
              httpOnly: ck.httpOnly,
              secure: ck.secure,
              sameSite: ck.sameSite,
              session: !ck.expirationDate,
              isSessionLike: isSession,
              issues: issues,
              removeUrl: ckProto + ckDom + (ck.path || "/")
            });
          }
          sendResponse({
            cookies: cookieAudit,
            setCookieIssues: hf.setCookieIssues || [],
            securityHeaders: hf.securityHeaders,
            reqHeaders: hf.reqHeaders
          });
        });
      } else {
        sendResponse({
          cookies: [],
          setCookieIssues: hf.setCookieIssues || [],
          securityHeaders: hf.securityHeaders,
          reqHeaders: hf.reqHeaders
        });
      }
      return true;
    }
    if (msg && msg.type === "BOXEDIN_GET_EXFIL_EVENTS") {
      var exfilTid = sender && sender.tab && typeof sender.tab.id === "number" ? sender.tab.id : -1;
      var events = exfilEventsByTab.get(exfilTid) || [];
      sendResponse({ events: events });
      return true;
    }
    if (msg && msg.type === "BOXEDIN_STORE_EXFIL_EVENT") {
      var eTid = sender && sender.tab && typeof sender.tab.id === "number" ? sender.tab.id : -1;
      if (eTid >= 0 && msg.event) {
        var evts = exfilEventsByTab.get(eTid);
        if (!evts) {
          evts = [];
          exfilEventsByTab.set(eTid, evts);
        }
        if (evts.length < MAX_EXFIL_EVENTS_PER_TAB) {
          evts.push(msg.event);
        }
      }
      sendResponse({ ok: true });
      return true;
    }
    if (msg && msg.type === "BOXEDIN_GET_INJECT_FINDINGS") {
      var injTid = sender && sender.tab && typeof sender.tab.id === "number" ? sender.tab.id : -1;
      var injF = injectFindingsByTab.get(injTid) || { csp: null, cors: [], reflectedParams: [] };
      sendResponse(injF);
      return true;
    }
    if (msg && msg.type === "BOXEDIN_STORE_INJECT_FINDING") {
      var iFTid = sender && sender.tab && typeof sender.tab.id === "number" ? sender.tab.id : -1;
      if (iFTid >= 0 && msg.finding) {
        var iFindings = injectFindingsByTab.get(iFTid);
        if (!iFindings) {
          iFindings = { csp: null, cors: [], reflectedParams: [], xss: [], csrf: [], openRedirects: [], mixedContent: [], formInventory: null };
          injectFindingsByTab.set(iFTid, iFindings);
        }
        var ft = msg.finding.type || msg.finding.subtype;
        if (ft === "xss" || ft === "xss-sink") {
          if (!iFindings.xss) iFindings.xss = [];
          if (iFindings.xss.length < 50) iFindings.xss.push(msg.finding);
        } else if (ft === "csrf" || ft === "csrf-missing") {
          if (!iFindings.csrf) iFindings.csrf = [];
          if (iFindings.csrf.length < 50) iFindings.csrf.push(msg.finding);
        } else if (ft === "reflected" || ft === "reflected-param") {
          if (!iFindings.reflectedParams) iFindings.reflectedParams = [];
          if (iFindings.reflectedParams.length < 50) iFindings.reflectedParams.push(msg.finding);
        } else if (ft === "open-redirect") {
          if (!iFindings.openRedirects) iFindings.openRedirects = [];
          var orFindings = msg.finding.findings || [];
          for (var ori = 0; ori < orFindings.length && iFindings.openRedirects.length < 50; ori++) {
            iFindings.openRedirects.push(orFindings[ori]);
          }
        } else if (ft === "mixed-content") {
          if (!iFindings.mixedContent) iFindings.mixedContent = [];
          var mcFindings = msg.finding.findings || [];
          for (var mci = 0; mci < mcFindings.length && iFindings.mixedContent.length < 100; mci++) {
            iFindings.mixedContent.push(mcFindings[mci]);
          }
        } else if (ft === "form-inventory") {
          iFindings.formInventory = { forms: msg.finding.forms || [], standaloneInputs: msg.finding.standaloneInputs || [] };
        }
      }
      sendResponse({ ok: true });
      return true;
    }
    if (msg && msg.type === "BOXEDIN_STORE_TECH_FINDING") {
      var tfTid = sender && sender.tab && typeof sender.tab.id === "number" ? sender.tab.id : -1;
      if (tfTid >= 0 && msg.finding) {
        var tFindings = techFindingsByTab.get(tfTid);
        if (!tFindings) {
          tFindings = [];
          techFindingsByTab.set(tfTid, tFindings);
        }
        var dupTech = false;
        for (var tdi = 0; tdi < tFindings.length; tdi++) {
          if (tFindings[tdi].name === msg.finding.name) { dupTech = true; break; }
        }
        if (!dupTech && tFindings.length < MAX_TECH_FINDINGS_PER_TAB) {
          tFindings.push(msg.finding);
        }
      }
      sendResponse({ ok: true });
      return true;
    }
    if (msg && msg.type === "BOXEDIN_UPDATE_TECH_VERSION") {
      var uvTid = sender && sender.tab && typeof sender.tab.id === "number" ? sender.tab.id : -1;
      if (uvTid >= 0 && msg.name && msg.version) {
        var uvFindings = techFindingsByTab.get(uvTid);
        if (uvFindings) {
          for (var uvi = 0; uvi < uvFindings.length; uvi++) {
            if (uvFindings[uvi].name === msg.name && !uvFindings[uvi].version) {
              uvFindings[uvi].version = msg.version;
              break;
            }
          }
        }
      }
      sendResponse({ ok: true });
      return true;
    }
    if (msg && msg.type === "BOXEDIN_GET_TECH_FINDINGS") {
      var gtTid = sender && sender.tab && typeof sender.tab.id === "number" ? sender.tab.id : -1;
      sendResponse({ findings: techFindingsByTab.get(gtTid) || [] });
      return true;
    }
    if (msg && msg.type === "BOXEDIN_STORE_API_FINDING") {
      var afTid = sender && sender.tab && typeof sender.tab.id === "number" ? sender.tab.id : -1;
      if (afTid >= 0 && msg.finding) {
        var aFindings = apiFindingsByTab.get(afTid);
        if (!aFindings) {
          aFindings = [];
          apiFindingsByTab.set(afTid, aFindings);
        }
        var dupApi = false;
        for (var adi = 0; adi < aFindings.length; adi++) {
          if (aFindings[adi].url === msg.finding.url) { dupApi = true; break; }
        }
        if (!dupApi && aFindings.length < MAX_API_FINDINGS_PER_TAB) {
          aFindings.push(msg.finding);
        }
      }
      sendResponse({ ok: true });
      return true;
    }
    if (msg && msg.type === "BOXEDIN_GET_API_FINDINGS") {
      var gaTid = sender && sender.tab && typeof sender.tab.id === "number" ? sender.tab.id : -1;
      var staticApis = apiFindingsByTab.get(gaTid) || [];
      var exfilApis = [];
      var exfilEvts = exfilEventsByTab.get(gaTid) || [];
      var seenExfil = {};
      var apiLikeRe = /\/api\/|\/v[0-9]+\/|\/graphql|\/rest\/|\/webhook/i;
      for (var eai = 0; eai < exfilEvts.length; eai++) {
        var ev = exfilEvts[eai];
        if (ev.url && (ev.subtype === "fetch" || ev.subtype === "xhr") && apiLikeRe.test(ev.url)) {
          if (!seenExfil[ev.url]) {
            seenExfil[ev.url] = true;
            exfilApis.push({ method: ev.method || "GET", url: ev.url, ts: ev.ts });
          }
        }
      }
      sendResponse({ findings: staticApis, exfilApis: exfilApis });
      return true;
    }
    if (msg && msg.type === "BOXEDIN_STORE_DEPS_FINDING") {
      var dpTid = sender && sender.tab && typeof sender.tab.id === "number" ? sender.tab.id : -1;
      if (dpTid >= 0 && msg.findings && Array.isArray(msg.findings)) {
        var dFindings = depsFindingsByTab.get(dpTid);
        if (!dFindings) {
          dFindings = [];
          depsFindingsByTab.set(dpTid, dFindings);
        }
        for (var dfi = 0; dfi < msg.findings.length && dFindings.length < MAX_DEPS_FINDINGS_PER_TAB; dfi++) {
          dFindings.push(msg.findings[dfi]);
        }
      }
      sendResponse({ ok: true });
      return true;
    }
    if (msg && msg.type === "BOXEDIN_GET_DEPS_FINDINGS") {
      var gdTid = sender && sender.tab && typeof sender.tab.id === "number" ? sender.tab.id : -1;
      sendResponse({ findings: depsFindingsByTab.get(gdTid) || [] });
      return true;
    }
    if (msg && msg.type === "BOXEDIN_STORE_TIMELINE_EVENT") {
      var tlTid = sender && sender.tab && typeof sender.tab.id === "number" ? sender.tab.id : -1;
      if (tlTid >= 0 && msg.event) {
        var tlEvents = timelineEventsByTab.get(tlTid);
        if (!tlEvents) {
          tlEvents = [];
          timelineEventsByTab.set(tlTid, tlEvents);
        }
        if (tlEvents.length < MAX_TIMELINE_EVENTS_PER_TAB) {
          tlEvents.push(msg.event);
        }
      }
      sendResponse({ ok: true });
      return true;
    }
    if (msg && msg.type === "BOXEDIN_GET_TIMELINE") {
      var gtlTid = sender && sender.tab && typeof sender.tab.id === "number" ? sender.tab.id : -1;
      var tlEvts = timelineEventsByTab.get(gtlTid) || [];
      var exfilTl = exfilEventsByTab.get(gtlTid) || [];
      var merged = [];
      for (var tei = 0; tei < tlEvts.length; tei++) merged.push(tlEvts[tei]);
      for (var xti = 0; xti < exfilTl.length; xti++) {
        merged.push({
          ts: exfilTl[xti].ts || 0,
          type: exfilTl[xti].subtype || "network",
          method: exfilTl[xti].method || "GET",
          url: exfilTl[xti].url || "",
          origin: "exfil"
        });
      }
      merged.sort(function (a, b) { return (a.ts || 0) - (b.ts || 0); });
      sendResponse({ events: merged });
      return true;
    }
    if (msg && msg.type === "BOXEDIN_FETCH_PATH_CONTENT") {
      var fetchUrl = msg.url || "";
      if (!fetchUrl) { sendResponse({ body: "", status: 0 }); return true; }
      fetch(fetchUrl, { method: "GET", credentials: "omit", redirect: "follow" })
        .then(function (resp) {
          var ct = resp.headers.get("content-type") || "";
          var status = resp.status;
          return resp.text().then(function (text) {
            var maxLen = 51200;
            sendResponse({
              body: text.length > maxLen ? text.slice(0, maxLen) + "\n\n--- truncated at " + maxLen + " bytes ---" : text,
              status: status,
              contentType: ct
            });
          });
        })
        .catch(function (err) {
          sendResponse({ body: "Error: " + String(err).slice(0, 200), status: 0, contentType: "" });
        });
      return true;
    }
    if (msg && msg.type === "BOXEDIN_PROBE_PATHS") {
      var ppOrigin = msg.origin || "";
      if (!ppOrigin) { sendResponse({ results: [] }); return true; }
      var probePaths = [
        { path: "/.env", risk: "critical", desc: "Environment variables / secrets" },
        { path: "/.git/HEAD", risk: "critical", desc: "Git repository exposed" },
        { path: "/.git/config", risk: "critical", desc: "Git config exposed" },
        { path: "/.svn/entries", risk: "high", desc: "SVN repository exposed" },
        { path: "/robots.txt", risk: "info", desc: "Robots directives" },
        { path: "/sitemap.xml", risk: "info", desc: "Sitemap index" },
        { path: "/.well-known/security.txt", risk: "info", desc: "Security contact info" },
        { path: "/security.txt", risk: "info", desc: "Security contact info (root)" },
        { path: "/wp-admin/", risk: "medium", desc: "WordPress admin panel" },
        { path: "/wp-login.php", risk: "medium", desc: "WordPress login" },
        { path: "/administrator/", risk: "medium", desc: "Admin panel" },
        { path: "/admin/", risk: "medium", desc: "Admin panel" },
        { path: "/graphql", risk: "medium", desc: "GraphQL endpoint" },
        { path: "/api/", risk: "info", desc: "API root" },
        { path: "/swagger.json", risk: "high", desc: "Swagger/OpenAPI spec" },
        { path: "/openapi.json", risk: "high", desc: "OpenAPI spec" },
        { path: "/api-docs", risk: "high", desc: "API documentation" },
        { path: "/.DS_Store", risk: "medium", desc: "macOS directory listing" },
        { path: "/crossdomain.xml", risk: "medium", desc: "Flash cross-domain policy" },
        { path: "/phpinfo.php", risk: "high", desc: "PHP info page" },
        { path: "/server-status", risk: "high", desc: "Apache server status" },
        { path: "/elmah.axd", risk: "high", desc: ".NET error logs" },
        { path: "/trace.axd", risk: "high", desc: ".NET trace logs" },
        { path: "/.htaccess", risk: "medium", desc: "Apache config" },
        { path: "/web.config", risk: "medium", desc: "IIS config" },
        { path: "/package.json", risk: "medium", desc: "Node.js manifest" },
        { path: "/composer.json", risk: "medium", desc: "PHP Composer manifest" },
        { path: "/debug/", risk: "high", desc: "Debug endpoint" },
        { path: "/actuator", risk: "high", desc: "Spring Boot actuator" },
        { path: "/actuator/health", risk: "medium", desc: "Spring Boot health" }
      ];
      var results = [];
      var completed = 0;
      var total = probePaths.length;
      for (var ppi = 0; ppi < total; ppi++) {
        (function (probe) {
          var probeUrl = ppOrigin + probe.path;
          fetch(probeUrl, { method: "HEAD", credentials: "omit", redirect: "follow" })
            .then(function (resp) {
              results.push({
                path: probe.path,
                status: resp.status,
                risk: probe.risk,
                desc: probe.desc,
                found: resp.status >= 200 && resp.status < 400
              });
            })
            .catch(function () {
              results.push({ path: probe.path, status: 0, risk: probe.risk, desc: probe.desc, found: false });
            })
            .finally(function () {
              completed++;
              if (completed === total) {
                results.sort(function (a, b) {
                  var order = { critical: 0, high: 1, medium: 2, info: 3 };
                  return (order[a.risk] || 4) - (order[b.risk] || 4);
                });
                sendResponse({ results: results });
              }
            });
        })(probePaths[ppi]);
      }
      return true;
    }
    if (msg && msg.type === "BOXEDIN_PROBE_CORS") {
      var corsOrigin = msg.origin || "";
      if (!corsOrigin) { sendResponse({ result: null }); return true; }
      fetch(corsOrigin, {
        method: "GET",
        credentials: "omit",
        headers: { "Origin": "https://evil-cors-test.example.com" }
      }).then(function (resp) {
        var acao = resp.headers.get("Access-Control-Allow-Origin") || "";
        var acac = resp.headers.get("Access-Control-Allow-Credentials") || "";
        var result = {
          acao: acao,
          acac: acac,
          vulnerable: false,
          reason: ""
        };
        if (acao === "*") {
          result.vulnerable = true;
          result.reason = "ACAO is wildcard (*)";
          if (acac.toLowerCase() === "true") {
            result.reason += " with Allow-Credentials: true (critical)";
          }
        } else if (acao === "https://evil-cors-test.example.com") {
          result.vulnerable = true;
          result.reason = "Origin reflected (accepts any origin)";
          if (acac.toLowerCase() === "true") {
            result.reason += " with Allow-Credentials: true (critical)";
          }
        } else if (acao === "null") {
          result.vulnerable = true;
          result.reason = "ACAO is 'null' — may be exploitable via sandboxed iframe";
        }
        sendResponse({ result: result });
      }).catch(function (err) {
        sendResponse({ result: { error: String(err).slice(0, 200) } });
      });
      return true;
    }
    if (msg && msg.type === "BOXEDIN_DNS_AUDIT") {
      var dnsDomain = msg.domain || "";
      if (!dnsDomain) { sendResponse({ findings: [] }); return true; }

      var dnsFindings = [];
      var dnsCompleted = 0;
      var dnsTotal = 0;
      var dnsBase = "https://dns.google/resolve?";

      function dnsQuery(name, type, cb) {
        dnsTotal++;
        fetch(dnsBase + "name=" + encodeURIComponent(name) + "&type=" + encodeURIComponent(type))
          .then(function (r) { return r.json(); })
          .then(function (data) { cb(data); })
          .catch(function () { cb(null); })
          .finally(function () {
            dnsCompleted++;
            if (dnsCompleted === dnsTotal) {
              dnsFindings.sort(function (a, b) {
                var order = { critical: 0, high: 1, medium: 2, info: 3 };
                return (order[a.risk] || 4) - (order[b.risk] || 4);
              });
              sendResponse({ findings: dnsFindings, domain: dnsDomain });
            }
          });
      }

      dnsQuery(dnsDomain, "TXT", function (data) {
        var answers = (data && data.Answer) || [];
        var spfRecord = null;
        for (var i = 0; i < answers.length; i++) {
          var txt = (answers[i].data || "").replace(/^"|"$/g, "");
          if (txt.indexOf("v=spf1") === 0) { spfRecord = txt; break; }
        }
        if (!spfRecord) {
          dnsFindings.push({ check: "SPF", risk: "critical", title: "No SPF record found", detail: "Domain can be spoofed in email. Add a TXT record with v=spf1." });
        } else {
          if (spfRecord.indexOf("+all") !== -1) {
            dnsFindings.push({ check: "SPF", risk: "critical", title: "SPF uses +all (pass all)", detail: "Any server can send email for this domain. Record: " + spfRecord });
          } else if (spfRecord.indexOf("?all") !== -1) {
            dnsFindings.push({ check: "SPF", risk: "high", title: "SPF uses ?all (neutral)", detail: "SPF result is neutral — does not reject unauthorized senders. Record: " + spfRecord });
          } else if (spfRecord.indexOf("~all") !== -1) {
            dnsFindings.push({ check: "SPF", risk: "medium", title: "SPF uses ~all (softfail)", detail: "Unauthorized senders get softfail (often still delivered). Consider -all. Record: " + spfRecord });
          } else if (spfRecord.indexOf("-all") !== -1) {
            dnsFindings.push({ check: "SPF", risk: "info", title: "SPF configured with -all (hardfail)", detail: "Good: unauthorized senders are rejected. Record: " + spfRecord });
          } else {
            dnsFindings.push({ check: "SPF", risk: "medium", title: "SPF record present but no all mechanism", detail: "Record: " + spfRecord });
          }
          var lookupCount = (spfRecord.match(/\b(include:|a:|mx:|ptr:|exists:)/g) || []).length;
          if (lookupCount > 8) {
            dnsFindings.push({ check: "SPF", risk: "medium", title: "SPF has " + lookupCount + " DNS lookups", detail: "SPF spec limits to 10 DNS lookups. Exceeding this causes permerror. Record: " + spfRecord });
          }
        }
      });

      dnsQuery("_dmarc." + dnsDomain, "TXT", function (data) {
        var answers = (data && data.Answer) || [];
        var dmarcRecord = null;
        for (var i = 0; i < answers.length; i++) {
          var txt = (answers[i].data || "").replace(/^"|"$/g, "");
          if (txt.indexOf("v=DMARC1") === 0) { dmarcRecord = txt; break; }
        }
        if (!dmarcRecord) {
          dnsFindings.push({ check: "DMARC", risk: "critical", title: "No DMARC record found", detail: "No policy to handle SPF/DKIM failures. Add _dmarc." + dnsDomain + " TXT v=DMARC1; p=reject; ..." });
        } else {
          var policyMatch = dmarcRecord.match(/;\s*p\s*=\s*(\w+)/);
          var policy = policyMatch ? policyMatch[1].toLowerCase() : "";
          if (policy === "none") {
            dnsFindings.push({ check: "DMARC", risk: "high", title: "DMARC policy is p=none (monitoring only)", detail: "Spoofed email is not rejected or quarantined. Record: " + dmarcRecord });
          } else if (policy === "quarantine") {
            dnsFindings.push({ check: "DMARC", risk: "info", title: "DMARC policy is p=quarantine", detail: "Spoofed email is quarantined (e.g., spam folder). Consider p=reject. Record: " + dmarcRecord });
          } else if (policy === "reject") {
            dnsFindings.push({ check: "DMARC", risk: "info", title: "DMARC policy is p=reject", detail: "Good: spoofed email is rejected outright. Record: " + dmarcRecord });
          } else {
            dnsFindings.push({ check: "DMARC", risk: "medium", title: "DMARC record present, policy unclear", detail: "Record: " + dmarcRecord });
          }
          if (dmarcRecord.indexOf("rua=") === -1) {
            dnsFindings.push({ check: "DMARC", risk: "medium", title: "DMARC missing aggregate report address (rua=)", detail: "Without rua=, you receive no reports on authentication results." });
          }
        }
      });

      var dkimSelectors = ["default._domainkey", "google._domainkey", "k1._domainkey", "selector1._domainkey", "selector2._domainkey", "s1._domainkey", "s2._domainkey", "dkim._domainkey", "mail._domainkey"];
      var dkimFound = [];
      var dkimDone = 0;
      for (var dki = 0; dki < dkimSelectors.length; dki++) {
        (function (sel) {
          dnsQuery(sel + "." + dnsDomain, "TXT", function (data) {
            var answers = (data && data.Answer) || [];
            for (var i = 0; i < answers.length; i++) {
              var txt = (answers[i].data || "").replace(/^"|"$/g, "");
              if (txt.indexOf("v=DKIM1") !== -1 || txt.indexOf("k=rsa") !== -1 || txt.indexOf("p=") !== -1) {
                dkimFound.push(sel);
                break;
              }
            }
            dkimDone++;
            if (dkimDone === dkimSelectors.length) {
              if (dkimFound.length === 0) {
                dnsFindings.push({ check: "DKIM", risk: "medium", title: "No DKIM records found for common selectors", detail: "Checked: " + dkimSelectors.join(", ") + ". DKIM may use a custom selector." });
              } else {
                dnsFindings.push({ check: "DKIM", risk: "info", title: "DKIM found: " + dkimFound.join(", "), detail: dkimFound.length + " selector(s) with DKIM records." });
              }
            }
          });
        })(dkimSelectors[dki]);
      }

      dnsQuery(dnsDomain, "CAA", function (data) {
        var answers = (data && data.Answer) || [];
        var caaRecords = [];
        for (var i = 0; i < answers.length; i++) {
          if (answers[i].type === 257) caaRecords.push(answers[i].data || "");
        }
        if (caaRecords.length === 0) {
          dnsFindings.push({ check: "CAA", risk: "medium", title: "No CAA records found", detail: "Any Certificate Authority can issue TLS certificates for this domain. Add CAA records to restrict issuance." });
        } else {
          dnsFindings.push({ check: "CAA", risk: "info", title: "CAA records present (" + caaRecords.length + ")", detail: caaRecords.join(" | ") });
        }
      });

      dnsQuery(dnsDomain, "MX", function (data) {
        var answers = (data && data.Answer) || [];
        var mxRecords = [];
        for (var i = 0; i < answers.length; i++) {
          if (answers[i].type === 15) mxRecords.push(answers[i].data || "");
        }
        if (mxRecords.length === 0) {
          dnsFindings.push({ check: "MX", risk: "info", title: "No MX records (no mail server)", detail: "Domain does not accept email directly." });
        } else {
          var mxStr = mxRecords.join(", ");
          var provider = "unknown";
          if (/google|gmail/i.test(mxStr)) provider = "Google Workspace";
          else if (/outlook|microsoft/i.test(mxStr)) provider = "Microsoft 365";
          else if (/protonmail|proton/i.test(mxStr)) provider = "ProtonMail";
          else if (/mimecast/i.test(mxStr)) provider = "Mimecast";
          else if (/barracuda/i.test(mxStr)) provider = "Barracuda";
          else if (/pphosted|proofpoint/i.test(mxStr)) provider = "Proofpoint";
          dnsFindings.push({ check: "MX", risk: "info", title: "Mail provider: " + provider, detail: mxStr });
        }
      });

      dnsQuery(dnsDomain, "NS", function (data) {
        var answers = (data && data.Answer) || [];
        var nsRecords = [];
        for (var i = 0; i < answers.length; i++) {
          if (answers[i].type === 2) nsRecords.push((answers[i].data || "").replace(/\.$/, ""));
        }
        if (nsRecords.length > 0) {
          var providers = {};
          for (var ni = 0; ni < nsRecords.length; ni++) {
            var parts = nsRecords[ni].split(".");
            var nsDomain = parts.length >= 2 ? parts.slice(-2).join(".") : nsRecords[ni];
            providers[nsDomain] = true;
          }
          var providerKeys = Object.keys(providers);
          if (providerKeys.length === 1) {
            dnsFindings.push({ check: "NS", risk: "medium", title: "Single NS provider: " + providerKeys[0], detail: "All nameservers at one provider. If it goes down, the entire domain is unreachable. NS: " + nsRecords.join(", ") });
          } else {
            dnsFindings.push({ check: "NS", risk: "info", title: "Nameservers (" + nsRecords.length + ")", detail: nsRecords.join(", ") });
          }
        }
      });

      dnsQuery(dnsDomain, "DNSKEY", function (data) {
        var answers = (data && data.Answer) || [];
        var ad = data && data.AD;
        if (answers.length > 0 || ad) {
          dnsFindings.push({ check: "DNSSEC", risk: "info", title: "DNSSEC is enabled", detail: answers.length + " DNSKEY record(s)." + (ad ? " AD flag set (authenticated data)." : "") });
        } else {
          dnsFindings.push({ check: "DNSSEC", risk: "medium", title: "DNSSEC not enabled", detail: "Domain is not DNSSEC-signed. DNS responses can be spoofed." });
        }
      });

      dnsQuery("www." + dnsDomain, "CNAME", function (data) {
        var answers = (data && data.Answer) || [];
        for (var i = 0; i < answers.length; i++) {
          if (answers[i].type === 5) {
            var target = (answers[i].data || "").replace(/\.$/, "");
            dnsFindings.push({ check: "CNAME", risk: "info", title: "www CNAME \u2192 " + target, detail: "www." + dnsDomain + " is a CNAME to " + target });
          }
        }
      });

      return true;
    }
    if (msg && msg.type === "BOXEDIN_EXPORT_ALL_FINDINGS") {
      var expTid = sender && sender.tab && typeof sender.tab.id === "number" ? sender.tab.id : -1;
      var report = {
        exportedAt: new Date().toISOString(),
        tabId: expTid,
        url: (sender && sender.tab) ? sender.tab.url || "" : "",
        auth: headerFindingsByTab.get(expTid) || {},
        exfil: exfilEventsByTab.get(expTid) || [],
        inject: injectFindingsByTab.get(expTid) || {},
        tech: techFindingsByTab.get(expTid) || [],
        apis: apiFindingsByTab.get(expTid) || [],
        deps: depsFindingsByTab.get(expTid) || [],
        timeline: timelineEventsByTab.get(expTid) || []
      };
      var sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      var injData = report.inject;
      if (injData.csp && injData.csp.missing) sevCounts.critical++;
      if (injData.cors) sevCounts.medium += injData.cors.length;
      if (injData.xss) sevCounts.critical += injData.xss.length;
      if (injData.csrf) sevCounts.medium += injData.csrf.length;
      if (injData.reflectedParams) sevCounts.high += injData.reflectedParams.length;
      if (injData.openRedirects) sevCounts.medium += injData.openRedirects.length;
      if (injData.mixedContent) sevCounts.low += injData.mixedContent.length;
      var authData = report.auth;
      if (authData.reqHeaders) {
        for (var ah = 0; ah < authData.reqHeaders.length; ah++) {
          if (authData.reqHeaders[ah].authOverHttp) sevCounts.critical++;
        }
      }
      var depsArr = report.deps;
      for (var ddi = 0; ddi < depsArr.length; ddi++) {
        if (depsArr[ddi].thirdParty && !depsArr[ddi].sri) sevCounts.medium++;
      }
      report.severitySummary = sevCounts;
      sendResponse({ report: report });
      return true;
    }
    if (msg && msg.type === "BOXEDIN_RESET_EXFIL_EVENTS") {
      var exRTid = sender && sender.tab && typeof sender.tab.id === "number" ? sender.tab.id : -1;
      if (exRTid >= 0) {
        exfilEventsByTab.delete(exRTid);
      }
      sendResponse({ ok: true });
      return true;
    }
    if (msg && msg.type === "BOXEDIN_REDTEAM_RESET") {
      var rTid = sender && sender.tab && typeof sender.tab.id === "number" ? sender.tab.id : -1;
      if (rTid >= 0) {
        headerFindingsByTab.delete(rTid);
        exfilEventsByTab.delete(rTid);
        injectFindingsByTab.delete(rTid);
        techFindingsByTab.delete(rTid);
        apiFindingsByTab.delete(rTid);
        depsFindingsByTab.delete(rTid);
        timelineEventsByTab.delete(rTid);
        capturedRequestsByTab.delete(rTid);
      }
      sendResponse({ ok: true });
      return true;
    }
    if (msg && msg.type === "BOXEDIN_GET_CAPTURED_REQUESTS") {
      var capTid = sender && sender.tab && typeof sender.tab.id === "number" ? sender.tab.id : -1;
      var reqs = capturedRequestsByTab.get(capTid) || [];
      sendResponse({ requests: reqs });
      return true;
    }
    if (msg && msg.type === "BOXEDIN_REPLAY_REQUEST") {
      (function () {
        var reqUrl = msg.url || "";
        var reqMethod = (msg.method || "GET").toUpperCase();
        var reqHeaders = {};
        var rawHeaders = msg.headers || {};
        var forbiddenHeaders = { "cookie": 1, "host": 1, "connection": 1, "content-length": 1 };
        var hk = Object.keys(rawHeaders);
        for (var hi = 0; hi < hk.length; hi++) {
          if (!forbiddenHeaders[hk[hi].toLowerCase()]) {
            reqHeaders[hk[hi]] = rawHeaders[hk[hi]];
          }
        }
        var reqBody = msg.body || "";
        var fetchOpts = {
          method: reqMethod,
          headers: reqHeaders,
          credentials: "include",
          redirect: "follow"
        };
        var skipBodyMethods = { GET: 1, HEAD: 1 };
        if (!skipBodyMethods[reqMethod] && reqBody) {
          fetchOpts.body = reqBody;
        }
        var startMs = Date.now();
        fetch(reqUrl, fetchOpts).then(function (resp) {
          var status = resp.status;
          var statusText = resp.statusText;
          var respHeaders = {};
          resp.headers.forEach(function (val, key) {
            respHeaders[key] = val;
          });
          return resp.text().then(function (bodyText) {
            sendResponse({
              ok: true,
              status: status,
              statusText: statusText,
              headers: respHeaders,
              body: bodyText.slice(0, 50000),
              elapsedMs: Date.now() - startMs
            });
          });
        }).catch(function (err) {
          sendResponse({
            ok: false,
            error: String(err && err.message ? err.message : err),
            elapsedMs: Date.now() - startMs
          });
        });
      })();
      return true;
    }
    return false;
  });

  chrome.storage.onChanged.addListener(function (changes, areaName) {
    if (areaName !== "local") return;
    if (changes[STORAGE_EXTENSION_ENABLED]) {
      extensionEnabled = changes[STORAGE_EXTENSION_ENABLED].newValue !== false;
      applyExtensionEnabledState(extensionEnabled);
    }
    if (changes[STORAGE_KEY]) {
      scheduleApplyUserDnrRules();
    }
    if (changes[STORAGE_BLOCKED_HOSTS]) {
      scheduleApplyHostBlockRules();
    }
    if (changes[STORAGE_CAPTURE_HOSTS]) {
      captureHostsEnabled = !!changes[STORAGE_CAPTURE_HOSTS].newValue;
    }
    if (changes[STORAGE_REDTEAM_ENABLED]) {
      redteamEnabled = !!changes[STORAGE_REDTEAM_ENABLED].newValue;
    }
  });

  /* onClicked no longer fires — the popup handles enable/disable. */

  if (chrome.webRequest && chrome.webRequest.onBeforeRequest) {
    try {
      chrome.webRequest.onBeforeRequest.addListener(
        function (details) {
          if (!extensionEnabled) return;
          if (details.tabId >= 0 && details.requestBody) {
            if (pendingBodiesByRequestId.size > MAX_PENDING_BODIES) {
              pendingBodiesByRequestId.delete(pendingBodiesByRequestId.keys().next().value);
            }
            var bodyText = "";
            var bodySize = 0;
            if (details.requestBody.formData) {
              var pfd = details.requestBody.formData;
              var bPairs = [];
              var pfKeys = Object.keys(pfd);
              for (var pk = 0; pk < pfKeys.length; pk++) {
                var pvals = pfd[pfKeys[pk]];
                if (Array.isArray(pvals)) {
                  for (var pv = 0; pv < pvals.length; pv++) {
                    bodySize += String(pvals[pv]).length;
                    bPairs.push(encodeURIComponent(pfKeys[pk]) + "=" + encodeURIComponent(pvals[pv]));
                  }
                }
              }
              bodyText = bPairs.join("&");
            }
            if (details.requestBody.raw) {
              for (var rb = 0; rb < details.requestBody.raw.length; rb++) {
                var rawBytes = details.requestBody.raw[rb].bytes;
                if (rawBytes) bodySize += rawBytes.byteLength;
              }
              if (!bodyText) {
                try {
                  var rawChunks = [];
                  for (var rc = 0; rc < details.requestBody.raw.length; rc++) {
                    if (details.requestBody.raw[rc].bytes) {
                      rawChunks.push(new TextDecoder().decode(details.requestBody.raw[rc].bytes));
                    }
                  }
                  if (rawChunks.length > 0) bodyText = rawChunks.join("");
                } catch (eBody) { /* ignore */ }
              }
            }
            pendingBodiesByRequestId.set(details.requestId, {
              method: details.method || "GET",
              bodySize: bodySize,
              bodyText: bodyText.slice(0, 50000)
            });
          }
          if (!captureHostsEnabled && !redteamEnabled) return;
          if (details.tabId < 0) return;
          try {
            var u = new URL(details.url);
            var host = u.hostname;
            if (!host) return;

            if (captureHostsEnabled) {
              var set = observedHostsByTab.get(details.tabId);
              if (!set) {
                set = new Set();
                observedHostsByTab.set(details.tabId, set);
              }
              if (set.size < MAX_UNIQUE_HOSTS_PER_TAB) {
                set.add(host);
              }
            }

            if (redteamEnabled) {
              var pendingBody = pendingBodiesByRequestId.get(details.requestId);
              var bodySize = pendingBody ? pendingBody.bodySize : 0;
              if (bodySize > 5000) {
                var evts = exfilEventsByTab.get(details.tabId);
                if (!evts) {
                  evts = [];
                  exfilEventsByTab.set(details.tabId, evts);
                }
                if (evts.length < MAX_EXFIL_EVENTS_PER_TAB) {
                  evts.push({
                    source: "background",
                    type: "exfil",
                    subtype: "large-request",
                    url: details.url.slice(0, 200),
                    host: host,
                    bodySize: bodySize,
                    method: details.method || "?",
                    ts: Date.now()
                  });
                }
              }
            }
          } catch (eUrl) {
            /* ignore */
          }
        },
        { urls: ["*://*/*"] },
        ["requestBody"]
      );
    } catch (eWr) {
      console.warn("[BoxedIn] webRequest listener:", eWr);
    }
  }

  if (chrome.webRequest && chrome.webRequest.onBeforeSendHeaders) {
    try {
      chrome.webRequest.onBeforeSendHeaders.addListener(
        function (details) {
          if (!extensionEnabled) return;
          if (details.tabId < 0) return;

          var allHeaders = {};
          if (details.requestHeaders) {
            for (var i = 0; i < details.requestHeaders.length; i++) {
              var h = details.requestHeaders[i];
              allHeaders[h.name] = h.value || "";
            }
          }

          var pending = pendingBodiesByRequestId.get(details.requestId);
          if (pending) pendingBodiesByRequestId.delete(details.requestId);
          var captured = capturedRequestsByTab.get(details.tabId);
          if (!captured) {
            captured = [];
            capturedRequestsByTab.set(details.tabId, captured);
          }
          if (captured.length < MAX_CAPTURED_REQUESTS_PER_TAB) {
            captured.push({
              url: details.url,
              method: (pending && pending.method) || details.method || "GET",
              headers: allHeaders,
              body: (pending && pending.bodyText) || "",
              ts: Date.now()
            });
          }

          if (!redteamEnabled) return;
          var authEntry = { url: details.url, ts: Date.now(), headers: {} };
          if (details.requestHeaders) {
            for (var ai = 0; ai < details.requestHeaders.length; ai++) {
              var ah = details.requestHeaders[ai];
              var lname = ah.name.toLowerCase();
              if (lname === "cookie" || lname === "authorization" || lname === "x-csrf-token") {
                authEntry.headers[lname] = ah.value || "";
              }
            }
          }
          var findings = headerFindingsByTab.get(details.tabId);
          if (!findings) {
            findings = { reqHeaders: [], respHeaders: [], securityHeaders: {} };
            headerFindingsByTab.set(details.tabId, findings);
          }
          if (Object.keys(authEntry.headers).length > 0 && findings.reqHeaders.length < MAX_HEADER_FINDINGS_PER_TAB) {
            try {
              var u = new URL(details.url);
              if (u.protocol === "http:" && authEntry.headers["authorization"]) {
                authEntry.authOverHttp = true;
              }
              if (authEntry.headers["authorization"]) {
                var av = authEntry.headers["authorization"];
                if (/^Bearer\s+eyJ/i.test(av)) authEntry.tokenType = "JWT";
                else if (/^Basic\s+/i.test(av)) authEntry.tokenType = "Basic";
                else if (/^Bearer\s+/i.test(av)) authEntry.tokenType = "Bearer";
                else authEntry.tokenType = "other";
              }
            } catch (eU) { /* ignore */ }
            findings.reqHeaders.push(authEntry);
          }
        },
        { urls: ["*://*/*"] },
        ["requestHeaders", "extraHeaders"]
      );
    } catch (eBs) {
      console.warn("[BoxedIn] onBeforeSendHeaders:", eBs);
    }
  }

  if (chrome.webRequest && chrome.webRequest.onHeadersReceived) {
    try {
      chrome.webRequest.onHeadersReceived.addListener(
        function (details) {
          if (!extensionEnabled || !redteamEnabled) return;
          if (details.tabId < 0) return;
          if (details.type !== "main_frame") return;
          var findings = headerFindingsByTab.get(details.tabId);
          if (!findings) {
            findings = { reqHeaders: [], respHeaders: [], securityHeaders: {} };
            headerFindingsByTab.set(details.tabId, findings);
          }
          var inject = injectFindingsByTab.get(details.tabId);
          if (!inject) {
            inject = { csp: null, cors: [], reflectedParams: [] };
            injectFindingsByTab.set(details.tabId, inject);
          }
          if (!details.responseHeaders) return;
          var techArr = techFindingsByTab.get(details.tabId);
          if (!techArr) {
            techArr = [];
            techFindingsByTab.set(details.tabId, techArr);
          }
          var TECH_HEADER_MAP = {
            "php": { category: "server", name: "PHP", notes: "Version disclosure, check for known CVEs" },
            "express": { category: "server", name: "Express", notes: "Default error pages leak stack traces" },
            "asp.net": { category: "server", name: "ASP.NET", notes: "ViewState deserialization, debug mode exposure" },
            "nginx": { category: "server", name: "Nginx", notes: "Version disclosure, misconfiguration checks" },
            "apache": { category: "server", name: "Apache", notes: "Version disclosure, mod_status/mod_info exposure" },
            "cloudflare": { category: "server", name: "Cloudflare", notes: "CDN — origin IP may still be discoverable" },
            "openresty": { category: "server", name: "OpenResty", notes: "Nginx-based, check for Lua script exposure" },
            "iis": { category: "server", name: "IIS", notes: "Version disclosure, check for known CVEs" },
            "gunicorn": { category: "server", name: "Gunicorn", notes: "Python WSGI server, check debug mode" },
            "uvicorn": { category: "server", name: "Uvicorn", notes: "Python ASGI server, check debug mode" },
            "kestrel": { category: "server", name: "Kestrel", notes: ".NET server, check for exposed endpoints" },
            "cowboy": { category: "server", name: "Cowboy", notes: "Erlang/Elixir server, check for version disclosure" },
            "jetty": { category: "server", name: "Jetty", notes: "Java servlet container, check for known CVEs" },
            "tomcat": { category: "server", name: "Tomcat", notes: "Default manager app, known CVEs, check /manager/html" },
            "litespeed": { category: "server", name: "LiteSpeed", notes: "Version disclosure, check for admin console exposure" },
            "caddy": { category: "server", name: "Caddy", notes: "Go server, check for exposed admin API" },
            "deno": { category: "server", name: "Deno", notes: "Deno runtime, check for permissions leakage" },
            "tornado": { category: "server", name: "Tornado", notes: "Python async server, check for debug mode" },
            "werkzeug": { category: "server", name: "Werkzeug", notes: "Flask debug server — check for exposed debugger PIN" },
            "flask": { category: "server", name: "Flask", notes: "Check for debug mode and exposed debugger" },
            "django": { category: "server", name: "Django", notes: "Check for DEBUG=True and admin panel" },
            "laravel": { category: "server", name: "Laravel", notes: "Check for APP_DEBUG=true and .env exposure" },
            "rails": { category: "server", name: "Ruby on Rails", notes: "Check for exposed routes and debug mode" },
            "phusion passenger": { category: "server", name: "Phusion Passenger", notes: "App server, check for version disclosure" },
            "next.js": { category: "server", name: "Next.js", notes: "Check _next/data exposure and API routes" },
            "nuxt": { category: "server", name: "Nuxt", notes: "Check __NUXT__ state and server route leakage" }
          };

          function pushTechIfNew(cat, tName, ver, ev, notes) {
            for (var ti = 0; ti < techArr.length; ti++) {
              if (techArr[ti].name === tName) return;
            }
            if (techArr.length < MAX_TECH_FINDINGS_PER_TAB) {
              techArr.push({ category: cat, name: tName, version: ver, evidence: ev, attackNotes: notes || "" });
            }
          }

          var COOKIE_TECH_MAP = {
            "phpsessid": { category: "server", name: "PHP", notes: "PHPSESSID cookie — PHP session" },
            "asp.net_sessionid": { category: "server", name: "ASP.NET", notes: "ASP.NET_SessionId cookie" },
            "jsessionid": { category: "server", name: "Java Servlet", notes: "JSESSIONID cookie — Java session" },
            "laravel_session": { category: "server", name: "Laravel", notes: "laravel_session cookie" },
            "xsrf-token": { category: "server", name: "Laravel", notes: "XSRF-TOKEN cookie (common in Laravel)" },
            "_rails-session": { category: "server", name: "Ruby on Rails", notes: "Rails session cookie" },
            "rack.session": { category: "server", name: "Ruby on Rails", notes: "Rack session cookie" },
            "csrftoken": { category: "server", name: "Django", notes: "Django CSRF cookie" },
            "django_language": { category: "server", name: "Django", notes: "Django language cookie" },
            "connect.sid": { category: "server", name: "Express", notes: "Express/Connect session cookie" },
            "_shopify_s": { category: "cms", name: "Shopify", notes: "Shopify session cookie" },
            "_shopify_y": { category: "cms", name: "Shopify", notes: "Shopify analytics cookie" },
            "wp-settings-": { category: "cms", name: "WordPress", notes: "WordPress settings cookie" },
            "wordpress_logged_in": { category: "cms", name: "WordPress", notes: "WordPress auth cookie" },
            "wordpress_test_cookie": { category: "cms", name: "WordPress", notes: "WordPress test cookie" },
            "drupal": { category: "cms", name: "Drupal", notes: "Drupal session cookie" },
            "joomla_user_state": { category: "cms", name: "Joomla", notes: "Joomla session cookie" }
          };

          for (var hi = 0; hi < details.responseHeaders.length; hi++) {
            var hdr = details.responseHeaders[hi];
            var hName = hdr.name.toLowerCase();
            var hVal = hdr.value || "";

            if (hName === "x-powered-by" || hName === "server") {
              var hLower = hVal.toLowerCase();
              var thKeys = Object.keys(TECH_HEADER_MAP);
              for (var tk = 0; tk < thKeys.length; tk++) {
                if (hLower.indexOf(thKeys[tk]) !== -1) {
                  var tm = TECH_HEADER_MAP[thKeys[tk]];
                  pushTechIfNew(tm.category, tm.name, hVal, hName + " header", tm.notes);
                }
              }
            }

            if (hName === "x-generator") {
              pushTechIfNew("cms", hVal.split("/")[0].trim(), hVal, "X-Generator header", "");
            }

            if (hName === "x-drupal-cache" || hName === "x-drupal-dynamic-cache") {
              pushTechIfNew("cms", "Drupal", null, hName + " header", "Drupalgeddon RCE history, module CVEs");
            }
            if (hName === "x-wordpress" || hName === "x-pingback") {
              pushTechIfNew("cms", "WordPress", null, hName + " header", "XML-RPC, wp-login brute force, plugin/theme CVEs");
            }
            if (hName === "x-shopify-stage" || hName === "x-shopid") {
              pushTechIfNew("cms", "Shopify", null, hName + " header", "Liquid template injection, API token leakage");
            }

            if (hName === "x-aspnet-version" || hName === "x-aspnetmvc-version") {
              pushTechIfNew("server", "ASP.NET", hVal, hName + " header", "Version disclosure, ViewState deserialization");
            }

            if (hName === "x-varnish") {
              pushTechIfNew("server", "Varnish", null, "X-Varnish header", "Cache server — check for cache poisoning");
            }
            if (hName === "via" && hVal.toLowerCase().indexOf("varnish") !== -1) {
              pushTechIfNew("server", "Varnish", null, "Via header", "Cache server — check for cache poisoning");
            }

            if (hName === "x-turbo-charged-by") {
              pushTechIfNew("server", "LiteSpeed", hVal, "X-Turbo-Charged-By header", "LiteSpeed cache detected");
            }

            if (hName === "set-cookie") {
              var ckName = (hVal.split("=")[0] || "").trim().toLowerCase();
              var ckKeys = Object.keys(COOKIE_TECH_MAP);
              for (var ck = 0; ck < ckKeys.length; ck++) {
                if (ckName.indexOf(ckKeys[ck]) !== -1 || ckName === ckKeys[ck]) {
                  var cm = COOKIE_TECH_MAP[ckKeys[ck]];
                  pushTechIfNew(cm.category, cm.name, null, "Set-Cookie: " + ckName, cm.notes);
                  break;
                }
              }
            }
          }

          var secH = {};
          var setCookies = [];
          var corsOrigin = null;
          var corsCreds = false;
          var cspRaw = null;
          var cspReportOnly = null;
          for (var i = 0; i < details.responseHeaders.length; i++) {
            var h = details.responseHeaders[i];
            var name = h.name.toLowerCase();
            var val = h.value || "";
            if (name === "strict-transport-security") secH.hsts = val;
            else if (name === "x-content-type-options") secH.xcto = val;
            else if (name === "x-frame-options") secH.xfo = val;
            else if (name === "content-security-policy") cspRaw = val;
            else if (name === "content-security-policy-report-only") cspReportOnly = val;
            else if (name === "access-control-allow-origin") corsOrigin = val;
            else if (name === "access-control-allow-credentials") corsCreds = val.toLowerCase() === "true";
            else if (name === "set-cookie") setCookies.push(val);
          }
          findings.securityHeaders = {
            hsts: secH.hsts || null,
            xcto: secH.xcto || null,
            xfo: secH.xfo || null,
            hasCsp: !!cspRaw,
            cspReportOnly: !!cspReportOnly && !cspRaw
          };
          findings.setCookieIssues = [];
          for (var sc = 0; sc < setCookies.length; sc++) {
            var cookie = setCookies[sc];
            var parts = cookie.split(";");
            var nameVal = (parts[0] || "").split("=");
            var cName = (nameVal[0] || "").trim().toLowerCase();
            var flags = cookie.toLowerCase();
            var isSession = /session|token|auth|sid|jwt/.test(cName);
            var issues = [];
            if (isSession && flags.indexOf("httponly") === -1) issues.push("missing HttpOnly");
            if (flags.indexOf("secure") === -1) issues.push("missing Secure");
            if (flags.indexOf("samesite=none") !== -1 && flags.indexOf("secure") === -1) issues.push("SameSite=None without Secure");
            if (issues.length > 0) {
              findings.setCookieIssues.push({ name: cName, issues: issues });
            }
          }
          if (cspRaw || cspReportOnly) {
            var cspStr = cspRaw || cspReportOnly;
            var directives = {};
            var cspIssues = [];
            var cspParts = cspStr.split(";");
            for (var cp = 0; cp < cspParts.length; cp++) {
              var trimmed = cspParts[cp].trim();
              if (!trimmed) continue;
              var spIdx = trimmed.indexOf(" ");
              var dName = spIdx > 0 ? trimmed.substring(0, spIdx) : trimmed;
              var dVal = spIdx > 0 ? trimmed.substring(spIdx + 1).trim() : "";
              directives[dName.toLowerCase()] = dVal;
            }
            var scriptSrc = directives["script-src"] || directives["default-src"] || "";
            if (/('unsafe-inline'|'unsafe-eval'|\*)/.test(scriptSrc)) {
              if (scriptSrc.indexOf("'unsafe-inline'") !== -1) cspIssues.push("script-src allows unsafe-inline");
              if (scriptSrc.indexOf("'unsafe-eval'") !== -1) cspIssues.push("script-src allows unsafe-eval");
              if (/(?:^|\s)\*(?:\s|$)/.test(scriptSrc)) cspIssues.push("script-src allows wildcard (*)");
            }
            if (!directives["frame-ancestors"]) cspIssues.push("missing frame-ancestors (clickjacking risk)");
            inject.csp = {
              raw: cspStr.length > 500 ? cspStr.slice(0, 497) + "..." : cspStr,
              reportOnly: !cspRaw && !!cspReportOnly,
              directives: directives,
              issues: cspIssues
            };
          } else {
            inject.csp = { raw: null, missing: true, issues: ["No CSP header present"] };
          }
          if (corsOrigin) {
            var corsIssues = [];
            if (corsOrigin === "*") corsIssues.push("Access-Control-Allow-Origin: * (allows any origin)");
            if (corsCreds && (corsOrigin === "*" || corsOrigin !== "null")) {
              corsIssues.push("Access-Control-Allow-Credentials: true with permissive origin");
            }
            if (corsIssues.length > 0) {
              inject.cors = corsIssues;
            }
          }
        },
        { urls: ["*://*/*"] },
        ["responseHeaders", "extraHeaders"]
      );
    } catch (eHr) {
      console.warn("[BoxedIn] onHeadersReceived:", eHr);
    }
  }

  if (chrome.tabs && chrome.tabs.onRemoved) {
    chrome.tabs.onRemoved.addListener(function (tabId) {
      observedHostsByTab.delete(tabId);
      headerFindingsByTab.delete(tabId);
      exfilEventsByTab.delete(tabId);
      injectFindingsByTab.delete(tabId);
      techFindingsByTab.delete(tabId);
      apiFindingsByTab.delete(tabId);
      depsFindingsByTab.delete(tabId);
      timelineEventsByTab.delete(tabId);
      capturedRequestsByTab.delete(tabId);
    });
  }

  if (chrome.runtime && chrome.runtime.onSuspend) {
    chrome.runtime.onSuspend.addListener(function () {
      if (flushStatsTimer !== null) {
        clearTimeout(flushStatsTimer);
        flushStatsTimer = null;
      }
      flushBlockStats();
    });
  }

  if (chrome.cookies && chrome.cookies.onChanged) {
    chrome.cookies.onChanged.addListener(function (changeInfo) {
      if (changeInfo.removed) return;
      var ck = changeInfo.cookie;
      if (!ck || !ck.name) return;
      for (var bi = 0; bi < blockedCookiesList.length; bi++) {
        var entry = blockedCookiesList[bi];
        if (entry.name === ck.name && (ck.domain === entry.domain || ck.domain === "." + entry.domain || "." + ck.domain === entry.domain)) {
          var proto = ck.secure ? "https://" : "http://";
          var dom = ck.domain.charAt(0) === "." ? ck.domain.slice(1) : ck.domain;
          chrome.cookies.remove({ url: proto + dom + (ck.path || "/"), name: ck.name }, function () {
            /* silently enforce */
          });
          break;
        }
      }
    });
  }

  chrome.storage.onChanged.addListener(function (changes, areaName) {
    if (areaName !== "local") return;
    if (changes[STORAGE_BLOCKED_COOKIES]) {
      blockedCookiesList = Array.isArray(changes[STORAGE_BLOCKED_COOKIES].newValue) ? changes[STORAGE_BLOCKED_COOKIES].newValue : [];
    }
  });

  initFromStorage();
})();
