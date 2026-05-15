---
layout: page
title: Tags
permalink: /tags
---

<section id="tags-section">
  {% assign sorted_tags = site.tags | sort %}

  <div class="post-tags" id="tag-filters">
    {% for tag in sorted_tags %}
      <a href="/tags#{{ tag[0] | slugify }}" class="tag" data-tag="{{ tag[0] | slugify }}">{{ tag[0] }} ({{ tag[1].size }})</a>
    {% endfor %}
  </div>

  <hr>

  {% for tag in sorted_tags %}
    <div class="tag-group" data-tag="{{ tag[0] | slugify }}">
      <h3 id="{{ tag[0] | slugify }}">{{ tag[0] }}</h3>
      <ul>
        {% for post in tag[1] %}
          <li>
            <time>{{ post.date | date: "%d %b %Y" }} - </time>
            <a href="{{ post.url | prepend: site.baseurl | replace: '//', '/' }}">{{ post.title }}</a>
          </li>
        {% endfor %}
      </ul>
    </div>
  {% endfor %}
</section>

<script>
function filterTags() {
  var hash = window.location.hash.substring(1);
  var groups = document.querySelectorAll('.tag-group');
  if (!hash) {
    groups.forEach(function(g) { g.style.display = ''; });
    return;
  }
  groups.forEach(function(g) {
    g.style.display = g.getAttribute('data-tag') === hash ? '' : 'none';
  });
}
window.addEventListener('hashchange', filterTags);
window.addEventListener('load', filterTags);
</script>
