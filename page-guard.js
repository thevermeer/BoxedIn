/**
 * Runs in the page JS world (MAIN), as early as document_start allows.
 * Stops fingerprint scripts from probing chrome-extension:// and similar
 * URLs, and blocks selected LinkedIn / third-party telemetry URLs.
 *
 * Script dropping: dynamically inserted <script> nodes that look like
 * extension scanners are not attached (so they do not run).
 * Parser-inserted scripts in the initial HTML may still run before hooks;
 * API patches below are the main defense for those.
 *
 * Memory: blocking network calls does not remove LinkedIn app bundles from
 * RAM. Bundles are still downloaded and parsed; telemetry paths fail fast.
 * To skip specific script files, add declarativeNetRequest redirect rules
 * in rules.json to extensionPath "/empty.js" (see empty.js). Wrong patterns
 * break the site.
 *
 * Limits: cannot stop server-side logic, native code, or probes that bypass
 * patched APIs. Side channels may still exist.
 *
 * Console: extension-scheme blocks are silent by default; set
 * __extensionProbeGuard.verboseExtensionBlocking for per-URL logs. Counts
 * are in __extensionProbeGuard.stats.extensionSchemeBlocked.
 */
(function () {
  "use strict";

  var LOG_PREFIX = "[extension-probe-guard]";

  /**
   * Returns `window.__extensionProbeGuard`, creating it with defaults for
   * `verboseExtensionBlocking` and `stats.extensionSchemeBlocked` when absent.
   */
  function ensureGuard() {
    try {
      var g = window.__extensionProbeGuard;
      if (!g || typeof g !== "object") {
        g = {};
        window.__extensionProbeGuard = g;
      }
      if (typeof g.verboseExtensionBlocking !== "boolean") {
        g.verboseExtensionBlocking = false;
      }
      if (!g.stats || typeof g.stats !== "object") {
        g.stats = {};
      }
      if (typeof g.stats.extensionSchemeBlocked !== "number") {
        g.stats.extensionSchemeBlocked = 0;
      }
      return g;
    } catch (_) {
      return {
        verboseExtensionBlocking: false,
        stats: { extensionSchemeBlocked: 0 },
      };
    }
  }

  ensureGuard();

  /**
   * Increments extension-scheme block stats; logs only when
   * `verboseExtensionBlocking` is true (avoids console spam when pages probe
   * many chrome-extension:// URLs).
   */
  function logExtensionSchemeBlock(action, detail) {
    var g = ensureGuard();
    g.stats.extensionSchemeBlocked += 1;
    if (g.verboseExtensionBlocking) {
      log(action, detail);
    }
  }

  /**
   * Emits one `console.info` line with LOG_PREFIX; optional second argument
   * is logged as a separate detail value.
   */
  function log(action, detail) {
    if (typeof console === "undefined" || !console.info) return;
    if (detail !== undefined && detail !== null && detail !== "") {
      console.info(LOG_PREFIX + " " + action, detail);
    } else {
      console.info(LOG_PREFIX + " " + action);
    }
  }

  /**
   * Truncates a string for log output (default max length 120), appending
   * an ellipsis when shortened.
   */
  function truncate(s, max) {
    max = max || 120;
    if (s == null) return "";
    s = String(s);
    if (s.length <= max) return s;
    return s.slice(0, max) + "…";
  }

  var PREFIXES = [
    "chrome-extension://",
    "moz-extension://",
    "safari-web-extension://",
    "edge-extension://",
  ];

  /**
   * Regex for many distinct chrome-extension:// plus 32 hex id paths in one
   * source (bundled extension-ID list probes).
   */
  var EXT_SCHEME_IN_SOURCE = /chrome-extension:\/\/[a-f0-9]{32}\//gi;
  /**
   * Regex for moz-extension:// paths in script text (Firefox extension
   * probes).
   */
  var MOZ_SCHEME_IN_SOURCE = /moz-extension:\/\/[a-f0-9-]+\//gi;
  var MIN_INLINE_LEN = 400;
  var MIN_SCHEME_HITS = 3;

  /**
   * True if `url` starts with a known extension scheme (chrome-extension,
   * moz-extension, safari-web-extension, edge-extension).
   */
  function isExtensionSchemeUrl(url) {
    if (url == null) return false;
    var s = typeof url === "string" ? url : String(url);
    for (var i = 0; i < PREFIXES.length; i++) {
      if (s.indexOf(PREFIXES[i]) === 0) return true;
    }
    return false;
  }

  /**
   * Resolves a URL string against `document.baseURI` to an absolute href.
   * On parse failure, returns `String(url)`.
   */
  function resolveUrlAbsolute(url) {
    if (url == null || url === "") return "";
    try {
      return new URL(
        String(url),
        typeof document !== "undefined" ? document.baseURI : undefined
      ).href;
    } catch (_) {
      return String(url);
    }
  }

  /**
   * Lowercase segment names allowed to bypass the opaque-token heuristic
   * (single path segment, length ≥10, both letter and digit). Add here if a
   * legitimate LinkedIn path is wrongly blocked.
   */
  var LINKEDIN_ALLOWED_OPAQUE_SEGMENTS = new Set([]);

  /**
   * True for single-segment paths that look like opaque tracking tokens
   * (e.g. /q5WiqtMRlw): length 10–96, [A-Za-z0-9_-]+, at least one digit and
   * one letter. Not expressible safely in declarativeNetRequest RE2; JS only.
   */
  function isLinkedInOpaqueTokenPath(pathname) {
    var m = pathname.match(/^\/([^/?#]+)\/?$/);
    if (!m) return false;
    var seg = m[1];
    if (seg.length < 10 || seg.length > 96) return false;
    if (!/^[A-Za-z0-9_-]+$/.test(seg)) return false;
    if (!/[0-9]/.test(seg) || !/[a-zA-Z]/.test(seg)) return false;
    if (LINKEDIN_ALLOWED_OPAQUE_SEGMENTS.has(seg.toLowerCase())) return false;
    return true;
  }

  /**
   * True for LinkedIn hostnames and blocklisted path prefixes (sensorCollect,
   * li/track, realtime connectivity tracking, tscp-serving) or opaque token
   * paths matched by `isLinkedInOpaqueTokenPath`.
   */
  function isLinkedInBlocklistedUrl(url) {
    if (!url) return false;
    try {
      var u = new URL(
        String(url),
        typeof document !== "undefined" ? document.baseURI : undefined
      );
      var h = u.hostname.toLowerCase();
      var onLinkedIn =
        h === "linkedin.com" || h.slice(-13) === ".linkedin.com";
      if (!onLinkedIn) return false;
      var p = u.pathname;
      if (p.indexOf("/sensorCollect") !== -1) return true;
      if (p.indexOf("/li/track") !== -1) return true;
      if (
        p.indexOf("/realtime/realtimeFrontendClientConnectivityTracking") !==
        -1
      )
        return true;
      if (p.indexOf("/tscp-serving") !== -1) return true;
      if (isLinkedInOpaqueTokenPath(p)) return true;
      return false;
    } catch (_) {
      return false;
    }
  }

  /**
   * True when the URL host is the PerimeterX protechts collector
   * (collector-pxdojv695v.protechts.net); blocks all paths on that host.
   */
  function isProtechtsCollectorUrl(url) {
    if (!url) return false;
    try {
      var u = new URL(
        String(url),
        typeof document !== "undefined" ? document.baseURI : undefined
      );
      return (
        u.hostname.toLowerCase() === "collector-pxdojv695v.protechts.net"
      );
    } catch (_) {
      return false;
    }
  }

  /**
   * Reads the URL from `fetch()` input: plain string, `URL`, `Request`, or
   * falls back to `String(input)`.
   */
  function requestUrlFromFetchInput(input) {
    if (input == null) return "";
    if (typeof input === "string") return input;
    if (typeof URL !== "undefined" && input instanceof URL) return input.href;
    if (typeof Request !== "undefined" && input instanceof Request)
      return input.url;
    return String(input);
  }

  /**
   * Counts how many times the global regex `re` matches in string `s`
   * (restarts lastIndex before counting).
   */
  function countMatches(re, s) {
    if (!s) return 0;
    re.lastIndex = 0;
    var n = 0;
    while (re.exec(s)) n++;
    return n;
  }

  /**
   * Heuristic for inline script text: long enough and many
   * chrome-extension://… or other extension-scheme substrings (bundled
   * extension-ID probe lists).
   */
  function looksLikeExtensionProbeSource(text) {
    if (!text || text.length < MIN_INLINE_LEN) return false;
    var c = countMatches(EXT_SCHEME_IN_SOURCE, text);
    var m = countMatches(MOZ_SCHEME_IN_SOURCE, text);
    if (c >= MIN_SCHEME_HITS || m >= MIN_SCHEME_HITS) return true;
    var raw = 0;
    var i = 0;
    while (i < PREFIXES.length) {
      var p = PREFIXES[i++];
      var pos = 0;
      while ((pos = text.indexOf(p, pos)) !== -1) {
        raw++;
        pos += p.length;
      }
    }
    return raw >= MIN_SCHEME_HITS;
  }

  /**
   * If `node` is a `<script>` that should not be attached, returns a short
   * human-readable reason; otherwise null. Used by DOM insertion hooks.
   */
  function scriptDropReason(node) {
    if (!node || node.nodeType !== 1) return null;
    if (String(node.tagName).toUpperCase() !== "SCRIPT") return null;
    var src = node.src || "";
    if (src && isExtensionSchemeUrl(src)) {
      return "blocked script (extension-scheme src): " + truncate(src);
    }
    if (src) return null;
    var text = node.textContent || "";
    if (looksLikeExtensionProbeSource(text)) {
      return (
        "blocked inline script (extension-probe heuristic, " +
        text.length +
        " chars)"
      );
    }
    return null;
  }

  /**
   * True when `scriptDropReason` is non-null for this node.
   */
  function shouldDropScriptElement(node) {
    return scriptDropReason(node) != null;
  }

  /**
   * Wraps `appendChild`, `insertBefore`, `replaceChild`, and when present
   * `Element.append` / `prepend` so dynamically inserted probe `<script>`s
   * matching `scriptDropReason` are never attached (parser-inserted scripts
   * are not affected).
   */
  function patchDomInsertion() {
    var np = typeof Node !== "undefined" ? Node.prototype : null;
    var ep = typeof Element !== "undefined" ? Element.prototype : null;
    if (!np) return;

    /**
     * Intercepts `appendChild` / `insertBefore` so blocked `<script>` nodes
     * are never inserted into the tree.
     */
    function wrapTwo(name) {
      var orig = np[name];
      if (typeof orig !== "function") return;
      np[name] = function (node, ref) {
        var why = scriptDropReason(node);
        if (why) {
          log("DOM " + name + " — dropped <script>", why);
          return node;
        }
        return orig.apply(this, arguments);
      };
    }

    /**
     * Patches `replaceChild` so dropped scripts return the old child per DOM
     * semantics when the new child is blocked.
     */
    function wrapReplaceChild() {
      var orig = np.replaceChild;
      if (typeof orig !== "function") return;
      np.replaceChild = function (node, child) {
        var why = scriptDropReason(node);
        if (why) {
          log("DOM replaceChild — dropped <script>", why);
          return child;
        }
        return orig.apply(this, arguments);
      };
    }

    wrapTwo("appendChild");
    wrapTwo("insertBefore");
    wrapReplaceChild();

    if (ep) {
      var append = ep.append;
      if (typeof append === "function") {
        ep.append = function () {
          var args = [];
          var i = 0;
          for (; i < arguments.length; i++) {
            var n = arguments[i];
            var why = scriptDropReason(n);
            if (why) {
              log("Element.append — dropped <script>", why);
              continue;
            }
            args.push(n);
          }
          return append.apply(this, args);
        };
      }
      var prepend = ep.prepend;
      if (typeof prepend === "function") {
        ep.prepend = function () {
          var args = [];
          var i = 0;
          for (; i < arguments.length; i++) {
            var n = arguments[i];
            var why = scriptDropReason(n);
            if (why) {
              log("Element.prepend — dropped <script>", why);
              continue;
            }
            args.push(n);
          }
          return prepend.apply(this, args);
        };
      }
    }
  }

  /**
   * Invalid minimal PNG data URL used to replace blocked `src` on images when
   * a real load must fail without hitting an extension URL.
   */
  var BROKEN_DATA_IMG =
    "data:image/png;base64,";

  /**
   * Wraps `window.fetch` to reject blocked extension-scheme, LinkedIn
   * blocklist, and protechts collector URLs before the request runs.
   */
  function patchFetch() {
    if (typeof window.fetch !== "function") return;
    var orig = window.fetch;
    window.fetch = function (input, init) {
      var raw = requestUrlFromFetchInput(input);
      var abs = resolveUrlAbsolute(raw);
      if (isExtensionSchemeUrl(abs)) {
        logExtensionSchemeBlock(
          "fetch blocked (extension scheme)",
          truncate(abs, 200)
        );
        return Promise.reject(new TypeError("Blocked extension-URL fetch"));
      }
      if (isLinkedInBlocklistedUrl(abs)) {
        log("fetch blocked (LinkedIn blocklist)", truncate(abs, 200));
        return Promise.reject(
          new TypeError("Blocked LinkedIn telemetry fetch")
        );
      }
      if (isProtechtsCollectorUrl(abs)) {
        log("fetch blocked (protechts collector)", truncate(abs, 200));
        return Promise.reject(
          new TypeError("Blocked protechts collector fetch")
        );
      }
      return orig.apply(this, arguments);
    };
  }

  /**
   * Wraps `XMLHttpRequest.prototype.open` to throw on the same blocked URL
   * classes as `patchFetch`.
   */
  function patchXHR() {
    var XHR = window.XMLHttpRequest;
    if (!XHR || !XHR.prototype) return;
    var origOpen = XHR.prototype.open;
    XHR.prototype.open = function (method, url) {
      var abs = resolveUrlAbsolute(url);
      if (isExtensionSchemeUrl(abs)) {
        logExtensionSchemeBlock(
          "XMLHttpRequest.open blocked (extension scheme)",
          truncate(abs, 200)
        );
        throw new TypeError("Blocked extension-URL XHR");
      }
      if (isLinkedInBlocklistedUrl(abs)) {
        log(
          "XMLHttpRequest.open blocked (LinkedIn blocklist)",
          truncate(abs, 200)
        );
        throw new TypeError("Blocked LinkedIn telemetry XHR");
      }
      if (isProtechtsCollectorUrl(abs)) {
        log(
          "XMLHttpRequest.open blocked (protechts collector)",
          truncate(abs, 200)
        );
        throw new TypeError("Blocked protechts collector XHR");
      }
      return origOpen.apply(this, arguments);
    };
  }

  /**
   * Wraps `navigator.sendBeacon` to return false for blocked URLs (same
   * policy as fetch/XHR).
   */
  function patchSendBeacon() {
    if (
      typeof navigator === "undefined" ||
      typeof navigator.sendBeacon !== "function"
    ) {
      return;
    }
    var orig = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (url, data) {
      var abs = resolveUrlAbsolute(url);
      if (isExtensionSchemeUrl(abs)) {
        logExtensionSchemeBlock(
          "sendBeacon blocked (extension scheme)",
          truncate(abs, 200)
        );
        return false;
      }
      if (isLinkedInBlocklistedUrl(abs)) {
        log("sendBeacon blocked (LinkedIn blocklist)", truncate(abs, 200));
        return false;
      }
      if (isProtechtsCollectorUrl(abs)) {
        log("sendBeacon blocked (protechts collector)", truncate(abs, 200));
        return false;
      }
      return orig(url, data);
    };
  }

  /**
   * Replaces `src` setter on `ctor.prototype` (image, iframe, script) to
   * neutralize extension-scheme and protechts collector URLs. `label` is used
   * only for logging and choosing `about:blank` vs broken image data.
   *
   * @param {Function|null} ctor - e.g. HTMLImageElement
   * @param {string} propName - always "src" here
   * @param {string} label - constructor name for logs
   */
  function patchSrcProperty(ctor, propName, label) {
    if (!ctor || !ctor.prototype) return;
    try {
      var proto = ctor.prototype;
      var desc = Object.getOwnPropertyDescriptor(proto, propName);
      if (!desc || !desc.set) return;
      var origSet = desc.set;
      Object.defineProperty(proto, propName, {
        configurable: true,
        enumerable: desc.enumerable,
        get: desc.get,
        set: function (v) {
          var abs = resolveUrlAbsolute(v);
          if (isExtensionSchemeUrl(abs)) {
            logExtensionSchemeBlock(
              (label || propName) + "." + propName + " neutralized",
              truncate(v, 200)
            );
            return origSet.call(this, BROKEN_DATA_IMG);
          }
          if (isProtechtsCollectorUrl(abs)) {
            log(
              (label || propName) + "." + propName + " neutralized (protechts)",
              truncate(v, 200)
            );
            if (
              label === "HTMLIFrameElement" ||
              label === "HTMLScriptElement"
            ) {
              return origSet.call(this, "about:blank");
            }
            return origSet.call(this, BROKEN_DATA_IMG);
          }
          return origSet.call(this, v);
        },
      });
    } catch (_) {
      /* ignore */
    }
  }

  /**
   * Replaces `href` setter on anchors or links to `about:blank` for blocked
   * extension-scheme or protechts URLs.
   *
   * @param {Function|null} ctor - HTMLAnchorElement or HTMLLinkElement
   * @param {string} label - name for log lines
   */
  function patchHrefProperty(ctor, label) {
    if (!ctor || !ctor.prototype) return;
    try {
      var proto = ctor.prototype;
      var desc = Object.getOwnPropertyDescriptor(proto, "href");
      if (!desc || !desc.set) return;
      var origSet = desc.set;
      Object.defineProperty(proto, "href", {
        configurable: true,
        enumerable: desc.enumerable,
        get: desc.get,
        set: function (v) {
          var abs = resolveUrlAbsolute(v);
          if (isExtensionSchemeUrl(abs)) {
            logExtensionSchemeBlock(
              (label || "element") + ".href neutralized",
              truncate(v, 200)
            );
            return origSet.call(this, "about:blank");
          }
          if (isProtechtsCollectorUrl(abs)) {
            log(
              (label || "element") + ".href neutralized (protechts)",
              truncate(v, 200)
            );
            return origSet.call(this, "about:blank");
          }
          return origSet.call(this, v);
        },
      });
    } catch (_) {
      /* ignore */
    }
  }

  /**
   * Wraps `Element.prototype.setAttribute` for `src` and `href` so attribute
   * assignment cannot bypass the same URL rules as property setters.
   */
  function patchSetAttribute() {
    var el = typeof Element !== "undefined" ? Element.prototype : null;
    if (!el || !el.setAttribute) return;
    var orig = el.setAttribute;
    el.setAttribute = function (name, value) {
      var n = String(name).toLowerCase();
      if ((n === "src" || n === "href") && typeof value === "string") {
        var abs = resolveUrlAbsolute(value);
        if (isExtensionSchemeUrl(abs)) {
          logExtensionSchemeBlock(
            "setAttribute(" + n + ") neutralized",
            truncate(value, 200)
          );
          if (n === "src") return orig.call(this, "src", BROKEN_DATA_IMG);
          return orig.call(this, "href", "about:blank");
        }
        if (isProtechtsCollectorUrl(abs)) {
          log(
            "setAttribute(" + n + ") neutralized (protechts)",
            truncate(value, 200)
          );
          if (n === "src") {
            var tag = String(this.tagName || "").toUpperCase();
            if (tag === "IFRAME" || tag === "SCRIPT") {
              return orig.call(this, "src", "about:blank");
            }
            return orig.call(this, "src", BROKEN_DATA_IMG);
          }
          return orig.call(this, "href", "about:blank");
        }
      }
      return orig.apply(this, arguments);
    };
  }

  patchFetch();
  patchXHR();
  patchSendBeacon();
  patchSrcProperty(
    typeof HTMLImageElement !== "undefined" ? HTMLImageElement : null,
    "src",
    "HTMLImageElement"
  );
  patchSrcProperty(
    typeof HTMLIFrameElement !== "undefined" ? HTMLIFrameElement : null,
    "src",
    "HTMLIFrameElement"
  );
  patchSrcProperty(
    typeof HTMLScriptElement !== "undefined" ? HTMLScriptElement : null,
    "src",
    "HTMLScriptElement"
  );
  patchHrefProperty(
    typeof HTMLAnchorElement !== "undefined" ? HTMLAnchorElement : null,
    "HTMLAnchorElement"
  );
  patchHrefProperty(
    typeof HTMLLinkElement !== "undefined" ? HTMLLinkElement : null,
    "HTMLLinkElement"
  );
  patchSetAttribute();
  patchDomInsertion();

  try {
    var g = ensureGuard();
    g.version = "1.9.0";
    g.loadedAt = Date.now();
    g.logPrefix = LOG_PREFIX;
    /**
     * Returns a fixed string so callers can verify the guard is present in
     * this frame.
     */
    g.check = function () {
      return "extension-probe-guard is injected in this frame";
    };
    /**
     * Adds a lowercase path segment to `LINKEDIN_ALLOWED_OPAQUE_SEGMENTS` at
     * runtime if an opaque-token path is wrongly blocked.
     */
    g.allowLinkedInOpaqueSegment = function (seg) {
      if (!seg) return;
      LINKEDIN_ALLOWED_OPAQUE_SEGMENTS.add(String(seg).toLowerCase());
    };
  } catch (_) {
    /* ignore */
  }

  log(
    "active — " +
      LOG_PREFIX +
      "; extension-scheme blocks silent (stats in " +
      "__extensionProbeGuard.stats; set verboseExtensionBlocking = true " +
      "for per-URL logs)"
  );
})();
