---
title: Project UNDERTOW - The Math Behind Calculating Priority Score for Manual Reverse Engineering
date: 2026-05-21 15:01:00 +0100
categories:
  - Vulnerability Research
  - Reverse Engineering
  - Tools
  - Pipelines
tags:
  - nvidia
  - dll-hijacking
  - binary-analysis
  - tooling
  - pipelines
  - defense
toc: true
---
Around a month ago, I [announced Project UNDERTOW](https://www.linkedin.com/posts/mark-konstantinov-641b4b22b_securityresearch-vulnerabilityresearch-reverseengineering-ugcPost-7445194282568704001-1GYu) for the first time. In that post, I explained some of the reasons why I was not going to publish the full Go source code together with the math, explained, formally in a paper even though everything was almost fully finished. 

However, after many considerations and overthinking - more than I should have, speaking with a very close friend (tbh, if it wasn't for him to convince me, I wouldn't have released it), I finally decided to make it public. Or at least the math.

And what about the source of the tool? - There is a part of it which deals with visualizing relations of files across version releases of software, import/export tables + some more "spice" as a Neo4j graph. In the end, this module proved to be, for some reason, more demanding than I wanted it and being a bit burnt-out over this project, I decided to leave it aside for some time. This is not forgotten and I hate leaving projects unfinished, so I will definitely get back to it.

Why am I releasing this, since the tool is not fully complete? - This close friend of me, convinced me, and now I also think the same way, that publishing the math part, at least, before everything is working, would allow me to touch-on, polish and fix mistakes, if someone points out something. Easy. 

Enough talk. Enjoy the paper. Algebra + Cybersecurity <3 

<a href="/assets/pdf/posts/2026-05-21-undertow-math-post/The-Mathematics-of-Project-UNDERTOW-WATERMARKED.pdf" class="glightbox" data-type="pdf" data-title="The Mathematics of Project UNDERTOW">The Mathematics of Project UNDERTOW</a>
![RaptX Team Logo](RAPTX-team-logo.png)

---

Bye from TFLL37
*Love from [Team RaptX](https://raptx.org/)*
