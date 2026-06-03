// nem tudo que parece ruído é ruído. boa sorte. 0x5c
(function () {
  var _0x3f = [0x37,0x76,0x92,0x8c,0x86,0x37,0x4f,0x79,0x89,0x6d,0x66,0x2c,0x43,0x8b,0x7e,0x89,0xb2,0xbf,0xa3,0xa0,0xa2,0xfd,0xc3,0xa3,0x05,0xeb,0xd2,0xd1,0xa4,0xdb,0xcd,0xeb,0xc5,0xbd,0x0e,0x07,0x39,0x2d,0x30,0x1a];
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
    "parabéns: o exploit é em VOCÊ. Isso se chama self-XSS. Não cole nada.\n\n" +
    "Curioso? Tem um segredo neste arquivo. unlock() revela.",
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
