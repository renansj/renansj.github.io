// Builds the table of contents from the post headings and adds a clickable
// anchor to each heading for deep linking. Same-origin script, allowed by the
// existing CSP (script-src 'self').
(function () {
  function slugify(text) {
    return text
      .toLowerCase()
      .trim()
      .replace(/[^\w\s-]/g, "")
      .replace(/\s+/g, "-");
  }

  document.addEventListener("DOMContentLoaded", function () {
    var body = document.querySelector(".post-body");
    var toc = document.querySelector(".toc");
    if (!body || !toc) return;

    var list = toc.querySelector(".toc-list");
    var headings = body.querySelectorAll("h2, h3");
    if (headings.length < 3) return; // not worth a TOC for short posts

    headings.forEach(function (h) {
      if (!h.id) h.id = slugify(h.textContent);

      // Clickable anchor on the heading itself.
      var a = document.createElement("a");
      a.href = "#" + h.id;
      a.className = "heading-anchor";
      a.textContent = "#";
      a.setAttribute("aria-label", "Link para esta seção");
      h.appendChild(a);

      // TOC entry (h3 indented under h2).
      var li = document.createElement("li");
      li.className = "toc-" + h.tagName.toLowerCase();
      var link = document.createElement("a");
      link.href = "#" + h.id;
      link.textContent = h.textContent.replace(/#$/, "");
      li.appendChild(link);
      list.appendChild(li);
    });

    toc.hidden = false;
  });

  // Reading progress bar: width tracks scroll position through the article.
  document.addEventListener("DOMContentLoaded", function () {
    var bar = document.getElementById("reading-progress");
    var body = document.querySelector(".post-body");
    if (!bar || !body) return;

    function update() {
      var max = document.documentElement.scrollHeight - window.innerHeight;
      var pct = max > 0 ? (window.scrollY / max) * 100 : 0;
      bar.style.width = pct + "%";
    }
    window.addEventListener("scroll", update, { passive: true });
    window.addEventListener("resize", update);
    update();
  });
})();
