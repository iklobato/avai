// The panels board: client-only state (collapsed rows, the Setup panel,
// alert settings, the "seen" cursor) and the control token header.
(function () {
  "use strict";

  var KEYS = {
    collapsed: "avai_board_collapsed",
    setup: "avai_board_setup",
    seen: "avai_board_seen",
    notified: "avai_board_notified",
    alerts: "avai_board_alerts",
    token: "avai_control_token",
  };
  var NOTIFY_EVERY_MS = 15000;
  var BEEP_HZ = 880;
  var BEEP_SECONDS = 0.15;

  function read(key, fallback) {
    var value = localStorage.getItem(key);
    return value === null ? fallback : value;
  }

  // --- the control token rides on every write (control and feedback) ---
  document.body.addEventListener("htmx:configRequest", function (event) {
    var path = event.detail.path || "";
    if (
      path.indexOf("/control") === 0 ||
      path.indexOf("/board/feedback") === 0
    ) {
      event.detail.headers["X-Avai-Token"] = read(KEYS.token, "");
    }
  });

  // --- collapsible rows ---
  function collapsedRows() {
    try {
      return JSON.parse(read(KEYS.collapsed, "[]"));
    } catch (e) {
      return [];
    }
  }
  function applyRows() {
    var closed = collapsedRows();
    document.querySelectorAll(".row[data-row]").forEach(function (row) {
      var isClosed = closed.indexOf(row.dataset.row) >= 0;
      row.dataset.collapsed = isClosed ? "true" : "false";
      row
        .querySelector(".row-head")
        .setAttribute("aria-expanded", isClosed ? "false" : "true");
    });
  }
  document.body.addEventListener("click", function (event) {
    var head = event.target.closest(".row-head");
    if (!head) return;
    var name = head.closest(".row").dataset.row;
    var closed = collapsedRows();
    var at = closed.indexOf(name);
    if (at >= 0) closed.splice(at, 1);
    else closed.push(name);
    localStorage.setItem(KEYS.collapsed, JSON.stringify(closed));
    applyRows();
  });

  // --- Setup panel open / closed ---
  function applySetup() {
    var panel = document.getElementById("setup");
    if (panel) panel.hidden = read(KEYS.setup, "open") !== "open";
  }
  document.body.addEventListener("click", function (event) {
    if (!event.target.closest("[data-toggle-setup]")) return;
    localStorage.setItem(
      KEYS.setup,
      read(KEYS.setup, "open") === "open" ? "closed" : "open",
    );
    applySetup();
  });

  // --- alert switch (browser pop-up and sound) ---
  function alertsOn() {
    return read(KEYS.alerts, "on") === "on";
  }
  function applySwitches() {
    document
      .querySelectorAll("[data-switch='alerts']")
      .forEach(function (button) {
        button.setAttribute("aria-checked", alertsOn() ? "true" : "false");
      });
    document
      .querySelectorAll("[data-switch-label='alerts']")
      .forEach(function (label) {
        label.textContent = alertsOn() ? "On" : "Off";
      });
  }
  document.body.addEventListener("click", function (event) {
    if (!event.target.closest("[data-switch='alerts']")) return;
    localStorage.setItem(KEYS.alerts, alertsOn() ? "off" : "on");
    if (
      alertsOn() &&
      window.Notification &&
      Notification.permission === "default"
    ) {
      Notification.requestPermission();
    }
    applySwitches();
  });

  // --- "Mark all seen" moves the cursor the alert panels read ---
  document.body.addEventListener("click", function (event) {
    var button = event.target.closest("[data-mark-seen]");
    if (!button) return;
    localStorage.setItem(KEYS.seen, button.dataset.markSeen);
    htmx.trigger(document.body, "avai:seen");
  });
  window.avaiSeen = function () {
    return read(KEYS.seen, "");
  };

  // --- copy buttons ---
  document.body.addEventListener("click", function (event) {
    var button = event.target.closest("[data-copy]");
    if (!button || !navigator.clipboard) return;
    navigator.clipboard.writeText(button.dataset.copy).then(function () {
      button.textContent = "Copied";
    });
  });

  // --- the selected finding stays highlighted ---
  document.body.addEventListener("click", function (event) {
    var pick = event.target.closest("[data-pick]");
    if (!pick) return;
    document.querySelectorAll("tr.is-selected").forEach(function (row) {
      row.classList.remove("is-selected");
    });
    var row = pick.closest("tr");
    if (row) row.classList.add("is-selected");
  });

  // --- browser notifications for new findings ---
  function beep() {
    var Audio = window.AudioContext || window.webkitAudioContext;
    if (!Audio) return;
    var context = new Audio();
    var tone = context.createOscillator();
    tone.frequency.value = BEEP_HZ;
    tone.connect(context.destination);
    tone.start();
    tone.stop(context.currentTime + BEEP_SECONDS);
  }
  function notify() {
    var since = read(KEYS.notified, "");
    fetch("/api/notifications/new?since=" + encodeURIComponent(since), {
      cache: "no-store",
    })
      .then(function (response) {
        return response.ok ? response.json() : null;
      })
      .then(function (body) {
        if (!body) return;
        localStorage.setItem(KEYS.notified, body.now);
        if (!since || !body.items.length || !alertsOn()) return;
        beep();
        if (window.Notification && Notification.permission === "granted") {
          var first = body.items[0];
          new Notification("avai: " + body.items.length + " new finding(s)", {
            body: first.verdict + ": " + (first.artifact || first.collector),
          });
        }
      })
      .catch(function () {});
  }

  document.body.addEventListener("htmx:afterSwap", function () {
    applyRows();
    applySetup();
    applySwitches();
  });
  applyRows();
  applySetup();
  applySwitches();
  notify();
  setInterval(notify, NOTIFY_EVERY_MS);
})();
