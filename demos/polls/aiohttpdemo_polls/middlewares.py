import aiohttp_jinja2
from aiohttp import web


async def handle_404(request, response):
    response = aiohttp_jinja2.render_template('404.html',
                                              request,
                                              {})
    return response


async def handle_500(request, response):
    response = aiohttp_jinja2.render_template('500.html',
                                              request,
                                              {})
    return response


def error_pages(overrides):
    async def middleware(app, handler):
        async def middleware_handler(request):
            try:
                response = await handler(request)
                override = overrides.get(response.status)
                if override is None:
                    return response
                else:
                    return await override(request, response)
            except web.HTTPException as ex:
                override = overrides.get(ex.status)
                if override is None:
                    raise
                else:
                    return await override(request, ex)
        return middleware_handler
    return middleware


def setup_middlewares(app):
    error_middleware = error_pages({404: handle_404,
                                    500: handle_500})
    app.middlewares.append(error_middleware)
