// Builds a real macOS-style title bar (traffic lights + language label + copy
// button) at the top of every code block. Same-origin script, allowed by the
// existing CSP (script-src 'self'); no inline code.
(function () {
  function langOf(block) {
    var m = (block.className || "").match(/language-(\w+)/);
    if (!m) return "";
    return m[1] === "plaintext" ? "shell" : m[1];
  }

  document.addEventListener("DOMContentLoaded", function () {
    var blocks = document.querySelectorAll(
      "div.highlighter-rouge, figure.highlight"
    );
    blocks.forEach(function (block) {
      var pre = block.querySelector("pre");
      if (!pre || block.querySelector(".code-titlebar")) return;

      var bar = document.createElement("div");
      bar.className = "code-titlebar";

      var dots = document.createElement("span");
      dots.className = "code-dots";
      bar.appendChild(dots);

      var lang = document.createElement("span");
      lang.className = "code-lang";
      lang.textContent = langOf(block);
      bar.appendChild(lang);

      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "copy-btn";
      btn.textContent = "copy";
      btn.addEventListener("click", function () {
        navigator.clipboard.writeText(pre.innerText).then(function () {
          btn.textContent = "copied";
          setTimeout(function () {
            btn.textContent = "copy";
          }, 1500);
        });
      });
      bar.appendChild(btn);

      block.insertBefore(bar, block.firstChild);
    });
  });
})();
