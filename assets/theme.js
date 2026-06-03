// Theme switcher. The chosen value is validated against a fixed allowlist before
// use, so a tampered localStorage value can never reach the DOM/CSS (XSS-safe).
(function () {
  var THEMES = [
    ["default", "default"],
    ["solarized-dark", "solarized dark"],
    ["solarized-light", "solarized light"],
    ["black-on-white", "black on white"],
    ["white-on-black", "white on black"],
    ["green-on-black", "green on black"]
  ];
  var KEY = "theme";
  var ALLOWED = THEMES.map(function (t) { return t[0]; });

  function safeGet() {
    try { var v = localStorage.getItem(KEY); return ALLOWED.indexOf(v) > -1 ? v : "default"; }
    catch (e) { return "default"; }
  }
  function apply(v) {
    if (ALLOWED.indexOf(v) === -1) v = "default";
    document.documentElement.setAttribute("data-theme", v);
  }

  apply(safeGet());

  document.addEventListener("DOMContentLoaded", function () {
    var mount = document.getElementById("theme-switcher");
    if (!mount) return;
    var sel = document.createElement("select");
    sel.setAttribute("aria-label", "Tema do site");
    sel.className = "theme-select";
    THEMES.forEach(function (t) {
      var o = document.createElement("option");
      o.value = t[0];
      o.textContent = t[1];
      sel.appendChild(o);
    });
    sel.value = safeGet();
    sel.addEventListener("change", function () {
      apply(sel.value);
      try { localStorage.setItem(KEY, sel.value); } catch (e) {}
    });
    mount.appendChild(sel);
  });
})();
