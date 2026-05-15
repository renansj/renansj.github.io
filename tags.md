---
layout: page
title: Tags
permalink: /tags
---

<section>
  {% assign sorted_tags = site.tags | sort %}
  {% for tag in sorted_tags %}
    <h3 id="{{ tag[0] | slugify }}">{{ tag[0] }}</h3>
    <ul>
      {% for post in tag[1] %}
        <li>
          <time>{{ post.date | date: "%d %b %Y" }} - </time>
          <a href="{{ post.url | prepend: site.baseurl | replace: '//', '/' }}">{{ post.title }}</a>
        </li>
      {% endfor %}
    </ul>
  {% endfor %}
</section>
