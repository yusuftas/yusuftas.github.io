---
title: "Convert Web Page to Text"
date: 2021-12-31
categories: 
  - "general-programming"
tags: 
  - "beautifulsoup"
  - "html-render"
  - "nlp"
  - "web-to-text"
  - "web2text"
---

It has been a while since I last published a post. Finally it is time to come back to this blog and keep learning new stuff I can share. Let's get back to business.

As the title suggests, we will take a URL of a web page and save that page in a text document. This is particularly useful when working with NLP based problems and you need textual information about something. Web is the best source of abundance of information, for example Wikipedia. But copying and pasting manually from web will not be efficient where you need to process a lot of pages. So here comes the solution, automate web to text conversion with little help from Python.

While looking for this, I came across **BeautifulSoup**. It is a great tool in Python for processing html. And it does have a function called **get\_text**, how lucky we are :D Here is a very short function for requesting a webpage and getting text:

```python
import urllib.request
from bs4 import BeautifulSoup

def Web2Text(url, outname):
    # Header for the http request
    user_agent = 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.0.7) Gecko/2009021910 Firefox/3.0.7'
    headers={'User-Agent':user_agent,} 

    # Request and read the html from the given url
    request  = urllib.request.Request(url,None,headers)
    response = urllib.request.urlopen(request)
    data = response.read() # HTML data of the web page's source

    # Clean html
    raw = BeautifulSoup(data).get_text()
    print(raw)

    with open(outname, 'w',  encoding="utf-8") as outf:
        outf.writelines(raw)
```

<!--more-->

User agent is the browser agent we are imitating. Then urllib request is used to read the webpage html. This html data is simply processed by BeautifulSoup to get the text out. Finally the text is written to a text file. Lets see this in action by converting a Wikipedia page:

```python
url = 'https://en.wikipedia.org/wiki/Grevillea_buxifolia'
output_name = 'test.txt'
Web2Text(url, output_name)
```

It should save the content of the page in a text file. You will unfortunately get a lot of junk as well since Wikipedia page contains many links, references, tables etc. There might be better ways to do this for Wikipedia pages, but in general this method worked good enough for me to get text from webpages. Part of the output I get for this page:

```
Family:

Proteaceae

Genus:

Grevillea

Species:

G. buxifolia

Binomial name

Grevillea buxifolia(Sm.) R.Br.

Grevillea buxifolia, commonly known as the grey spider flower, is a species of the family Proteaceae. It grows in coastal New South Wales, Australia. First described in 1793 by James Edward Smith, he gave the new species the name Embothrium buxifolium. It is widely cultivated and contains a number[clarification needed] of subspecies and cultivars. These vary most in the presentation of the attractive flower.

Description[edit]
The species forms a short shrub, three or four feet high. The numerous branches are covered in a reddish or brown hair and many leaves.  Flowers sit at the termination of these: yellowish and white, pendulous star-shaped petals, set to appear in November.
The flowers of the plant sit alone, erect in umbels, on stalks covered in reddish brown hairs. The corolla is likewise clothed and is partly fused to form a cavity. This interior is white and the petals are otherwise very pale to yellow; this spills above the hairy parts.  The single elliptic leaves are veiny, with a very rough dark green upper; margins entire and roll to the downy underside. These are arranged, almost directly to the stem, alternate and numerous up the branches.  They end in a little sharp point.

References[edit]

"Grevillea buxifolia". Plant Name Details. IPNI. Retrieved 2007-07-29. Basionym: Proteaceae Embothrium buxifolium Sm. Spec. Bot. New Holland 1793
"Grevillea buxifolia". Grevillea page. (ASGAP). 14 February 2006. Archived from the original on 2007-07-16. Retrieved 2007-08-01. G.buxifolia subsp. buxifolia and subsp. phylicoides are both well known in cultivation and are generally reliable and attractive shrubs
External links[edit]
```

And this is where I will finish this post. I have found out this beautiful library BeautifulSoup and wanted to share how it can be used to extract text from webpages. Hopefully I will find a good use for all the text I will collect :) (hint: nl\*) And as always keep learning.
