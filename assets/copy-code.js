// Adds a "copy" button to every code block. Same-origin script, so it is allowed
// by the existing CSP (script-src 'self'); no inline code, no CSP change needed.
(function () {
  document.addEventListener("DOMContentLoaded", function () {
    var blocks = document.querySelectorAll(
      "div.highlighter-rouge, figure.highlight"
    );
    blocks.forEach(function (block) {
      var code = block.querySelector("pre");
      if (!code) return;

      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "copy-btn";
      btn.textContent = "copy";

      btn.addEventListener("click", function () {
        navigator.clipboard.writeText(code.innerText).then(function () {
          btn.textContent = "copied";
          setTimeout(function () {
            btn.textContent = "copy";
          }, 1500);
        });
      });

      block.appendChild(btn);
    });
  });
})();
