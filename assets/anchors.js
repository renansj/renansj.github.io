// Builds the TOC from post headings, numbers it to match the CSS counter,
// adds heading anchors, scroll-spy (highlight current section) and a reading
// progress bar. Same-origin script, allowed by CSP (script-src 'self').
(function () {
  function slugify(text) {
    return text.toLowerCase().trim()
      .replace(/[^\w\s-]/g, "").replace(/\s+/g, "-");
  }

  document.addEventListener("DOMContentLoaded", function () {
    var body = document.querySelector(".post-body");
    var toc = document.querySelector(".toc");
    if (!body || !toc) return;

    var list = toc.querySelector(".toc-list");
    var headings = body.querySelectorAll("h2, h3");
    if (headings.length < 3) return;

    var h2 = 0, h3 = 0;
    var entries = []; // {id, link} for scroll-spy

    headings.forEach(function (h) {
      if (!h.id) h.id = slugify(h.textContent);

      var a = document.createElement("a");
      a.href = "#" + h.id;
      a.className = "heading-anchor";
      a.textContent = "#";
      a.setAttribute("aria-label", "Link para esta seção");
      h.appendChild(a);

      var num;
      if (h.tagName === "H2") { h2++; h3 = 0; num = h2 + ". "; }
      else { h3++; num = h2 + "." + h3 + " "; }

      var li = document.createElement("li");
      li.className = "toc-" + h.tagName.toLowerCase();
      var link = document.createElement("a");
      link.href = "#" + h.id;
      link.textContent = num + h.textContent.replace(/#$/, "");
      li.appendChild(link);
      list.appendChild(li);
      entries.push({ el: h, link: link });
    });

    toc.hidden = false;

    // Scroll-spy: mark the heading nearest the top as active.
    function spy() {
      var pos = window.scrollY + 100;
      var active = entries[0];
      for (var i = 0; i < entries.length; i++) {
        if (entries[i].el.offsetTop <= pos) active = entries[i];
      }
      entries.forEach(function (e) {
        e.link.classList.toggle("toc-active", e === active);
      });
    }
    window.addEventListener("scroll", spy, { passive: true });
    spy();
  });

  // Reading progress bar.
  document.addEventListener("DOMContentLoaded", function () {
    var bar = document.getElementById("reading-progress");
    var body = document.querySelector(".post-body");
    if (!bar || !body) return;
    function update() {
      var max = document.documentElement.scrollHeight - window.innerHeight;
      bar.style.width = (max > 0 ? (window.scrollY / max) * 100 : 0) + "%";
    }
    window.addEventListener("scroll", update, { passive: true });
    window.addEventListener("resize", update);
    update();
  });
})();
