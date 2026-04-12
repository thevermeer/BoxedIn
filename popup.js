(function () {
  "use strict";

  var KEY = "extensionEnabled";

  var toggleBtn = document.getElementById("toggleBtn");
  var statusLabel = document.getElementById("statusLabel");
  var optionsBtn = document.getElementById("optionsBtn");

  function applyState(enabled) {
    if (toggleBtn) {
      toggleBtn.className = enabled ? "toggle-btn toggle-btn--on" : "toggle-btn toggle-btn--off";
    }
    if (statusLabel) {
      statusLabel.textContent = enabled ? "Enabled" : "Disabled";
      statusLabel.className = enabled ? "status-label status-label--on" : "status-label status-label--off";
    }
  }

  chrome.storage.local.get([KEY], function (items) {
    applyState(items[KEY] !== false);
  });

  if (toggleBtn) {
    toggleBtn.addEventListener("click", function () {
      chrome.storage.local.get([KEY], function (items) {
        var next = items[KEY] === false;
        var patch = {};
        patch[KEY] = next;
        chrome.storage.local.set(patch);
        applyState(next);
      });
    });
  }

  if (optionsBtn) {
    optionsBtn.addEventListener("click", function () {
      chrome.runtime.openOptionsPage();
      window.close();
    });
  }

  chrome.storage.onChanged.addListener(function (changes, areaName) {
    if (areaName === "local" && changes[KEY]) {
      applyState(changes[KEY].newValue !== false);
    }
  });
})();
