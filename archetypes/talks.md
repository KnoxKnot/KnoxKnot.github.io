--- 
title: "{{ replace .Name "-" " " | title }}"
date: {{ .Date }}
draft: true
author: ""
description: "" 
summary: "" #Used on Archive Pages and in RSS
images: ["post-cover.png"] #images used for social media preview. comma separate each image path enclosed in double quotes
thumbnail: "images/thumbnail.jpg" #featured-image of the page. i will recommend using same image for both preview and thumbnail
tags: [] #comma separated tags enclosed in double quotes. also used for SEO.
categories: [] #comma separated categories enclosed in double quotes.
series: [] #A taxonomy used to list "See Also" Section in Opengraph Templates
slug: "" #Similar to WordPress's Slug (the end part of the url)
disableComments: false
---
