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
        title: extensionEnabled
          ? "BoxedIn — click to turn off"
          : "BoxedIn is off — click to turn on",
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
        return d;
      })(),
      function (items) {
        captureHostsEnabled = !!items[STORAGE_CAPTURE_HOSTS];
        extensionEnabled = items[STORAGE_EXTENSION_ENABLED] !== false;
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
  });

  if (chrome.action && chrome.action.onClicked) {
    chrome.action.onClicked.addListener(function () {
      var patch = {};
      patch[STORAGE_EXTENSION_ENABLED] = !extensionEnabled;
      chrome.storage.local.set(patch);
    });
  }

  if (chrome.webRequest && chrome.webRequest.onBeforeRequest) {
    try {
      chrome.webRequest.onBeforeRequest.addListener(
        function (details) {
          if (!extensionEnabled || !captureHostsEnabled) return;
          if (details.tabId < 0) return;
          try {
            var u = new URL(details.url);
            var host = u.hostname;
            if (!host) return;
            var set = observedHostsByTab.get(details.tabId);
            if (!set) {
              set = new Set();
              observedHostsByTab.set(details.tabId, set);
            }
            if (set.size >= MAX_UNIQUE_HOSTS_PER_TAB) return;
            set.add(host);
          } catch (eUrl) {
            /* ignore */
          }
        },
        { urls: ["*://*/*"] },
        []
      );
    } catch (eWr) {
      console.warn("[BoxedIn] webRequest listener:", eWr);
    }
  }

  if (chrome.tabs && chrome.tabs.onRemoved) {
    chrome.tabs.onRemoved.addListener(function (tabId) {
      observedHostsByTab.delete(tabId);
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

  initFromStorage();
})();
