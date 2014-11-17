import asyncio
import os
import string
from aiohttp.abc import AbstractRouter, AbstractMatchInfo
from aiohttp.web import (Application, Response, HTTPNotFound,
                         HTTPFound, HTTPForbidden)


class Item:
    def __init__(self, path):
        self.path = os.path.abspath(path)
        self.is_dir = os.path.isdir(self.path)

    def child(self, request, subpath):
        if self.is_dir:
            path = os.path.join(self.path, subpath)
            if os.path.exists(path):
                return Item(path)
        raise HTTPNotFound(request)

    def parent(self, request):
        return Item(os.path.dirname(self.path))

    @asyncio.coroutine
    def html(self, request):
        try:
            if self.is_dir:
                lst = []
                for i in sorted(os.listdir(self.path)):
                    if i in ('.', '..'):
                        continue
                    child = self.child(request, i)
                    child_url = yield from request.app.router.reverse('GET',
                                                                      child)
                    lst.append('<li><a href="{}">{}</a>'.format(child_url, i))
                content = "<ul>" + "\n".join(lst) + "</ul>"
            else:
                content = "<h2>Terminal</h2>"

            tmpl = string.Template("""\
            <html>
              <head>
                <title>$name</title>
              </head>
              <body>
                <h1>$name</h1>
                <a href="$parent">Up</a>
                <p>$content</p>
              </body>
            </html>
            """)
            parent = self.parent(request)
            parent_url = yield from request.app.router.reverse('GET', parent)
            html = tmpl.substitute(name=self.path, parent=parent_url,
                                   content=content)
            resp = Response(request, html.encode('utf-8'))
            resp.content_type = "text/html"
            resp.charset = 'utf-8'
            return resp
        except PermissionError:
            raise HTTPForbidden(request)


class MatchInfo(AbstractMatchInfo):
    def __init__(self, resource):
        self._resource = resource

    @property
    def handler(self):
        return self._resource.html

    @property
    def endpoint(self):
        return self._resource


class Traversal(AbstractRouter):

    def __init__(self):
        self.root = Item('/')

    @asyncio.coroutine
    def resolve(self, request):
        path = request.path
        if path.startswith('/~'):
            path = path[1:]
        path = os.path.expanduser(path)
        if path != request.path:
            raise HTTPFound(request, location=path)
        assert request.method == "GET", (request, request.method)
        current = self.root
        for item in path.split('/'):
            current = current.child(request, item)
        return MatchInfo(current)

    @asyncio.coroutine
    def reverse(self, method, endpoint):
        assert method == "GET", method
        return endpoint.path


@asyncio.coroutine
def init(loop):
    app = Application(router=Traversal(), loop=loop)

    srv = yield from loop.create_server(app.make_handler, '127.0.0.1', 8080)
    print("Server started at http://127.0.0.1:8080")
    return srv

loop = asyncio.get_event_loop()
loop.run_until_complete(init(loop))
loop.run_forever()
