# Embedded file name: lib\web\debugerror.py
"""
pretty debug errors
(part of web.py)

portions adapted from Django <djangoproject.com> 
Copyright (c) 2005, the Lawrence Journal-World
Used under the modified BSD license:
http://www.xfree86.org/3.3.6/COPYRIGHT2.html#5
"""
__all__ = ['debugerror', 'djangoerror', 'emailerrors']
import sys, pprint, traceback
from .template import Template
from .net import websafe
from .utils import sendmail, safestr
from . import webapi as web
from .py3helpers import urljoin, PY2
if PY2:

    def update_globals_template(t, globals):
        t.t.func_globals.update(globals)


else:

    def update_globals_template(t, globals):
        t.t.__globals__.update(globals)


import os, os.path
whereami = os.path.join(os.getcwd(), __file__)
whereami = os.path.sep.join(whereami.split(os.path.sep)[:-1])
djangoerror_t = '$def with (exception_type, exception_value, frames)\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">\n<html lang="en">\n<head>\n  <meta http-equiv="content-type" content="text/html; charset=utf-8" />\n  <meta name="robots" content="NONE,NOARCHIVE" />\n  <title>$exception_type at $ctx.path</title>\n  <style type="text/css">\n    html * { padding:0; margin:0; }\n    body * { padding:10px 20px; }\n    body * * { padding:0; }\n    body { font:small sans-serif; }\n    body>div { border-bottom:1px solid #ddd; }\n    h1 { font-weight:normal; }\n    h2 { margin-bottom:.8em; }\n    h2 span { font-size:80%; color:#666; font-weight:normal; }\n    h3 { margin:1em 0 .5em 0; }\n    h4 { margin:0 0 .5em 0; font-weight: normal; }\n    table { \n        border:1px solid #ccc; border-collapse: collapse; background:white; }\n    tbody td, tbody th { vertical-align:top; padding:2px 3px; }\n    thead th { \n        padding:1px 6px 1px 3px; background:#fefefe; text-align:left; \n        font-weight:normal; font-size:11px; border:1px solid #ddd; }\n    tbody th { text-align:right; color:#666; padding-right:.5em; }\n    table.vars { margin:5px 0 2px 40px; }\n    table.vars td, table.req td { font-family:monospace; }\n    table td.code { width:100%;}\n    table td.code div { overflow:hidden; }\n    table.source th { color:#666; }\n    table.source td { \n        font-family:monospace; white-space:pre; border-bottom:1px solid #eee; }\n    ul.traceback { list-style-type:none; }\n    ul.traceback li.frame { margin-bottom:1em; }\n    div.context { margin: 10px 0; }\n    div.context ol { \n        padding-left:30px; margin:0 10px; list-style-position: inside; }\n    div.context ol li { \n        font-family:monospace; white-space:pre; color:#666; cursor:pointer; }\n    div.context ol.context-line li { color:black; background-color:#ccc; }\n    div.context ol.context-line li span { float: right; }\n    div.commands { margin-left: 40px; }\n    div.commands a { color:black; text-decoration:none; }\n    #summary { background: #ffc; }\n    #summary h2 { font-weight: normal; color: #666; }\n    #explanation { background:#eee; }\n    #template, #template-not-exist { background:#f6f6f6; }\n    #template-not-exist ul { margin: 0 0 0 20px; }\n    #traceback { background:#eee; }\n    #requestinfo { background:#f6f6f6; padding-left:120px; }\n    #summary table { border:none; background:transparent; }\n    #requestinfo h2, #requestinfo h3 { position:relative; margin-left:-100px; }\n    #requestinfo h3 { margin-bottom:-1em; }\n    .error { background: #ffc; }\n    .specific { color:#cc3300; font-weight:bold; }\n  </style>\n  <script type="text/javascript">\n  //<!--\n    function getElementsByClassName(oElm, strTagName, strClassName){\n        // Written by Jonathan Snook, http://www.snook.ca/jon; \n        // Add-ons by Robert Nyman, http://www.robertnyman.com\n        var arrElements = (strTagName == "*" && document.all)? document.all :\n        oElm.getElementsByTagName(strTagName);\n        var arrReturnElements = new Array();\n        strClassName = strClassName.replace(/\\-/g, "\\-");\n        var oRegExp = new RegExp("(^|\\s)" + strClassName + "(\\s|$$)");\n        var oElement;\n        for(var i=0; i<arrElements.length; i++){\n            oElement = arrElements[i];\n            if(oRegExp.test(oElement.className)){\n                arrReturnElements.push(oElement);\n            }\n        }\n        return (arrReturnElements)\n    }\n    function hideAll(elems) {\n      for (var e = 0; e < elems.length; e++) {\n        elems[e].style.display = \'none\';\n      }\n    }\n    window.onload = function() {\n      hideAll(getElementsByClassName(document, \'table\', \'vars\'));\n      hideAll(getElementsByClassName(document, \'ol\', \'pre-context\'));\n      hideAll(getElementsByClassName(document, \'ol\', \'post-context\'));\n    }\n    function toggle() {\n      for (var i = 0; i < arguments.length; i++) {\n        var e = document.getElementById(arguments[i]);\n        if (e) {\n          e.style.display = e.style.display == \'none\' ? \'block\' : \'none\';\n        }\n      }\n      return false;\n    }\n    function varToggle(link, id) {\n      toggle(\'v\' + id);\n      var s = link.getElementsByTagName(\'span\')[0];\n      var uarr = String.fromCharCode(0x25b6);\n      var darr = String.fromCharCode(0x25bc);\n      s.innerHTML = s.innerHTML == uarr ? darr : uarr;\n      return false;\n    }\n    //-->\n  </script>\n</head>\n<body>\n\n$def dicttable (d, kls=\'req\', id=None):\n    $ items = d and list(d.items()) or []\n    $items.sort()\n    $:dicttable_items(items, kls, id)\n        \n$def dicttable_items(items, kls=\'req\', id=None):\n    $if items:\n        <table class="$kls"\n        $if id: id="$id"\n        ><thead><tr><th>Variable</th><th>Value</th></tr></thead>\n        <tbody>\n        $for k, v in items:\n            <tr><td>$k</td><td class="code"><div>$prettify(v)</div></td></tr>\n        </tbody>\n        </table>\n    $else:\n        <p>No data.</p>\n\n<div id="summary">\n  <h1>$exception_type at $ctx.path</h1>\n  <h2>$exception_value</h2>\n  <table><tr>\n    <th>Python</th>\n    <td>$frames[0].filename in $frames[0].function, line $frames[0].lineno</td>\n  </tr><tr>\n    <th>Web</th>\n    <td>$ctx.method $ctx.home$ctx.path</td>\n  </tr></table>\n</div>\n<div id="traceback">\n<h2>Traceback <span>(innermost first)</span></h2>\n<ul class="traceback">\n$for frame in frames:\n    <li class="frame">\n    <code>$frame.filename</code> in <code>$frame.function</code>\n    $if frame.context_line is not None:\n        <div class="context" id="c$frame.id">\n        $if frame.pre_context:\n            <ol start="$frame.pre_context_lineno" class="pre-context" id="pre$frame.id">\n            $for line in frame.pre_context:\n                <li onclick="toggle(\'pre$frame.id\', \'post$frame.id\')">$line</li>\n            </ol>\n            <ol start="$frame.lineno" class="context-line"><li onclick="toggle(\'pre$frame.id\', \'post$frame.id\')">$frame.context_line <span>...</span></li></ol>\n        $if frame.post_context:\n            <ol start=\'${frame.lineno + 1}\' class="post-context" id="post$frame.id">\n            $for line in frame.post_context:\n                <li onclick="toggle(\'pre$frame.id\', \'post$frame.id\')">$line</li>\n            </ol>\n      </div>\n    \n    $if frame.vars:\n        <div class="commands">\n        <a href=\'#\' onclick="return varToggle(this, \'$frame.id\')"><span>&#x25b6;</span> Local vars</a>\n        $# $inspect.formatargvalues(*inspect.getargvalues(frame[\'tb\'].tb_frame))\n        </div>\n        $:dicttable(frame.vars, kls=\'vars\', id=(\'v\' + str(frame.id)))\n      </li>\n  </ul>\n</div>\n\n<div id="requestinfo">\n$if ctx.output or ctx.headers:\n    <h2>Response so far</h2>\n    <h3>HEADERS</h3>\n    $:dicttable_items(ctx.headers)\n\n    <h3>BODY</h3>\n    <p class="req" style="padding-bottom: 2em"><code>\n    $ctx.output\n    </code></p>\n  \n<h2>Request information</h2>\n\n<h3>INPUT</h3>\n$:dicttable(web.input(_unicode=False))\n\n<h3 id="cookie-info">COOKIES</h3>\n$:dicttable(web.cookies())\n\n<h3 id="meta-info">META</h3>\n$ newctx = [(k, v) for (k, v) in ctx.iteritems() if not k.startswith(\'_\') and not isinstance(v, dict)]\n$:dicttable(dict(newctx))\n\n<h3 id="meta-info">ENVIRONMENT</h3>\n$:dicttable(ctx.env)\n</div>\n\n<div id="explanation">\n  <p>\n    You\'re seeing this error because you have <code>web.config.debug</code>\n    set to <code>True</code>. Set that to <code>False</code> if you don\'t want to see this.\n  </p>\n</div>\n\n</body>\n</html>\n'
djangoerror_r = None

def djangoerror():
    global djangoerror_r

    def _get_lines_from_file(filename, lineno, context_lines):
        """
        Returns context_lines before and after lineno from file.
        Returns (pre_context_lineno, pre_context, context_line, post_context).
        """
        try:
            source = open(filename).readlines()
            lower_bound = max(0, lineno - context_lines)
            upper_bound = lineno + context_lines
            pre_context = [ line.strip('\n') for line in source[lower_bound:lineno] ]
            context_line = source[lineno].strip('\n')
            post_context = [ line.strip('\n') for line in source[lineno + 1:upper_bound] ]
            return (lower_bound,
             pre_context,
             context_line,
             post_context)
        except (OSError, IOError, IndexError):
            return (None,
             [],
             None,
             [])

        return None

    exception_type, exception_value, tback = sys.exc_info()
    frames = []
    while tback is not None:
        filename = tback.tb_frame.f_code.co_filename
        function = tback.tb_frame.f_code.co_name
        lineno = tback.tb_lineno - 1
        lineno += tback.tb_frame.f_locals.get('__lineoffset__', 0)
        pre_context_lineno, pre_context, context_line, post_context = _get_lines_from_file(filename, lineno, 7)
        if '__hidetraceback__' not in tback.tb_frame.f_locals:
            frames.append(web.storage({'tback': tback,
             'filename': filename,
             'function': function,
             'lineno': lineno,
             'vars': tback.tb_frame.f_locals,
             'id': id(tback),
             'pre_context': pre_context,
             'context_line': context_line,
             'post_context': post_context,
             'pre_context_lineno': pre_context_lineno}))
        tback = tback.tb_next

    frames.reverse()

    def prettify(x):
        try:
            out = pprint.pformat(x)
        except Exception as e:
            out = '[could not display: <' + e.__class__.__name__ + ': ' + str(e) + '>]'

        return out

    if djangoerror_r is None:
        djangoerror_r = Template(djangoerror_t, filename=__file__, filter=websafe)
    t = djangoerror_r
    globals = {'ctx': web.ctx,
     'web': web,
     'dict': dict,
     'str': str,
     'prettify': prettify}
    update_globals_template(t, globals)
    return t(exception_type, exception_value, frames)


def debugerror():
    """
    A replacement for `internalerror` that presents a nice page with lots
    of debug information for the programmer.
    
    (Based on the beautiful 500 page from [Django](http://djangoproject.com/), 
    designed by [Wilson Miner](http://wilsonminer.com/).)
    """
    return web._InternalError(djangoerror())


def emailerrors(to_address, olderror, from_address = None):
    """
    Wraps the old `internalerror` handler (pass as `olderror`) to 
    additionally email all errors to `to_address`, to aid in
    debugging production websites.
    
    Emails contain a normal text traceback as well as an
    attachment containing the nice `debugerror` page.
    """
    from_address = from_address or to_address

    def emailerrors_internal():
        error = olderror()
        tb = sys.exc_info()
        error_name = tb[0]
        error_value = tb[1]
        tb_txt = ''.join(traceback.format_exception(*tb))
        path = web.ctx.path
        request = web.ctx.method + ' ' + web.ctx.home + web.ctx.fullpath
        message = '\n%s\n\n%s\n\n' % (request, tb_txt)
        sendmail('your buggy site <%s>' % from_address, 'the bugfixer <%s>' % to_address, 'bug: %(error_name)s: %(error_value)s (%(path)s)' % locals(), message, attachments=[dict(filename='bug.html', content=safestr(djangoerror()))])
        return error

    return emailerrors_internal


if __name__ == '__main__':
    urls = ('/', 'index')
    from .application import application
    app = application(urls, globals())
    app.internalerror = debugerror

    class index:

        def GET(self):
            thisdoesnotexist


    app.run()