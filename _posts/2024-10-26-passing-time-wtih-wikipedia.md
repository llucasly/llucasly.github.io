---
layout: post
title:  "Wikipedia: A Fun Way to Pass the Time" 
date:   2024-10-26 22:43:00 +1000
categories: Reading
---

One of my recent favourite pastimes is to read through a selection of the 500 curated Wikipedia articles available <a href="https://endwalker.com/archive.html" target="_blank" rel="noopener noreferrer">here</a>


It's a guilty pleasure of mine, a form of "productive" procrasination. 

I encourage you to find an article to read the next time you're bored. Instead of endless scrolling you can go down a [Wiki Rabbit Hole](https://en.wikipedia.org/wiki/Wiki_rabbit_hole). 

Just search for a random number generator online, set it's min max to 1-500 and open the corresponding Wikpedia article. Alternatively, jump right in with this randomly generated number (updates each time the page refreshes): <strong id="random-number">1</strong>

<script>
    function generateRandomNumber() {
        return Math.floor(Math.random() * 500) + 1;
    }
    document.getElementById('random-number').textContent = generateRandomNumber();
</script>

I gurantee you'll learn something new-- it may not be entirely useful, but you'll pick up plenty of fun little facts along the way.

