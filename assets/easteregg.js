// Easter eggs. Same-origin script, allowed by CSP (script-src 'self').
// 1) Konami code -> a few seconds of Matrix rain.
// 2) An ironic console warning aimed at an AppSec audience.
(function () {
  /* ---- Console trap (ironic, on brand for an AppSec blog) ---- */
  var s1 = "color:#b5e853;font-size:20px;font-family:monospace";
  var s2 = "color:#9aa4b0;font-size:13px;font-family:monospace";
  console.log("%c$ whoami", s1);
  console.log(
    "%cVocê abriu o console num blog sobre XSS. Que poético.\n" +
    "Se alguém te mandou COLAR algo aqui prometendo hackear o Insta de alguém,\n" +
    "parabéns: o exploit é em VOCÊ. Isso se chama self-XSS. Não cole nada.\n\n" +
    "Agora, se você veio fuçar de curioso: respeito. Tem uma flag escondida\n" +
    "em algum lugar deste site. Boa sorte. (dica: nem todo segredo está no JS)",
    s2
  );

  /* ---- Konami code -> Matrix rain ---- */
  var seq = [38, 38, 40, 40, 37, 39, 37, 39, 66, 65];
  var pos = 0;
  document.addEventListener("keydown", function (e) {
    pos = e.keyCode === seq[pos] ? pos + 1 : 0;
    if (pos === seq.length) { pos = 0; matrix(); }
  });

  function matrix() {
    if (document.getElementById("matrix-egg")) return;
    var c = document.createElement("canvas");
    c.id = "matrix-egg";
    c.style.cssText =
      "position:fixed;inset:0;z-index:9999;background:#000;pointer-events:none";
    document.body.appendChild(c);
    var ctx = c.getContext("2d");
    function size() { c.width = innerWidth; c.height = innerHeight; }
    size();

    var chars = "01アイウエカ$>_#@&%".split("");
    var fs = 16;
    var cols = Math.floor(c.width / fs);
    var drops = new Array(cols).fill(1);

    var timer = setInterval(function () {
      ctx.fillStyle = "rgba(0,0,0,0.08)";
      ctx.fillRect(0, 0, c.width, c.height);
      ctx.fillStyle = "#b5e853";
      ctx.font = fs + "px monospace";
      for (var i = 0; i < drops.length; i++) {
        ctx.fillText(chars[Math.floor(Math.random() * chars.length)], i * fs, drops[i] * fs);
        if (drops[i] * fs > c.height && Math.random() > 0.975) drops[i] = 0;
        drops[i]++;
      }
    }, 50);

    setTimeout(function () { clearInterval(timer); c.remove(); }, 5000);
  }
})();
