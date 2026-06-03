// nem tudo que parece ruído é ruído. boa sorte. 0x5c
(function () {
  var _0x3f = [0x2f,0x6c,0x35,0x7d,0x52,0x8c,0x48,0x5b,0x93,0x74,0x89,0x3c,0x95,0x2f,0x90,0x67,0x7d,0x48,0xaa,0xbf,0xf4,0x9e,0xe4,0xca,0x9d,0xcf,0xbe,0xef,0x94,0xfb,0xa5,0xdb,0xf2,0xaf,0x02,0xbb,0x12,0x07,0x39,0x2d,0x30,0x1a];
  function _0xd(_0xa, _0xk) {
    var _0xr = _0xa.slice().reverse(), _0xs = "";
    for (var _0xi = 0; _0xi < _0xr.length; _0xi++)
      _0xs += String.fromCharCode(((_0xr[_0xi] - _0xi) & 0xff) ^ ((_0xk + _0xi * 7) & 0xff));
    return _0xs;
  }
  window.unlock = function () { return _0xd(_0x3f, 0x5c); };

  var s1 = "color:#b5e853;font-size:20px;font-family:monospace";
  var s2 = "color:#9aa4b0;font-size:13px;font-family:monospace";
  console.log("%c$ whoami", s1);
  console.log(
    "%cVocê abriu o console num blog de AppSec. Faz sentido.\n" +
    "Mas se alguém te mandou COLAR algo aqui prometendo hackear o Insta de alguém,\n" +
    "parabéns: o exploit é em VOCÊ. Isso se chama self-XSS. Não cole nada.",
    s2
  );

  var seq = [38, 38, 40, 40, 37, 39, 37, 39, 66, 65], pos = 0;
  document.addEventListener("keydown", function (e) {
    pos = e.keyCode === seq[pos] ? pos + 1 : 0;
    if (pos === seq.length) { pos = 0; matrix(); }
  });

  function matrix() {
    if (document.getElementById("matrix-egg")) return;
    var c = document.createElement("canvas");
    c.id = "matrix-egg";
    c.style.cssText = "position:fixed;inset:0;z-index:9999;background:#000;pointer-events:none";
    document.body.appendChild(c);
    var ctx = c.getContext("2d");
    c.width = innerWidth; c.height = innerHeight;
    var chars = "01アイウエカ$>_#@&%".split(""), fs = 16;
    var drops = new Array(Math.floor(c.width / fs)).fill(1);
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
