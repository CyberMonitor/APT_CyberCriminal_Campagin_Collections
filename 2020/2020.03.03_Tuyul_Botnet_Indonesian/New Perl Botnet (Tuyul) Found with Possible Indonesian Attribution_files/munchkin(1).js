/*
 * Copyright (c) 2007-2018, Marketo, Inc. All rights reserved.
 * See https://developers.marketo.com/MunchkinLicense.pdf for license terms
 * Marketo marketing automation web activity tracking script
 * Version: prod r801
 */
 (function(b){if(!b.Munchkin){var c=b.document,e=[],k,l={fallback:"157"},g=[],m=function(){if(!k){for(;0<e.length;){var f=e.shift();b.MunchkinTracker[f[0]].apply(b.MunchkinTracker,f[1])}k=!0}},n=function(f){var a=c.createElement("script"),b=c.getElementsByTagName("base")[0]||c.getElementsByTagName("script")[0];a.type="text/javascript";a.async=!0;a.src=f;a.onreadystatechange=function(){"complete"!==this.readyState&&"loaded"!==this.readyState||m()};a.onload=m;b.parentNode.insertBefore(a,b)},h={ASSOCIATE_LEAD:"ASSOCIATE_LEAD",
CLICK_LINK:"CLICK_LINK",VISIT_WEB_PAGE:"visitWebPage",init:function(b){var a;a=l[b];if(!a&&0<g.length){a=b;var c=0,d;if(0!==a.length)for(d=0;d<a.length;d+=1)c+=a.charCodeAt(d);a=g[c%g.length]}a||(a=l.fallback);e.push(["init",arguments]);"150"===a?n("//munchkin-cdn.marketo.net/"+a+"/munchkin.js"):n("//munchkin.marketo.net/"+a+"/munchkin.js")}},p=function(b){return h[b]=function(){e.push([b,arguments])}};b.mktoMunchkinFunction=p("munchkinFunction");p("createTrackingCookie");b.Munchkin=h;b.mktoMunchkin=
h.init}})(window);
