import asyncio
from aiohttp import web
from aiohttp.sse import sse


@sse(heartbeat=10, json=True)
async def stream_numbers(request, resp):
    # Push 10 events once per second
    for i in range(10):
        await resp.send({"value": i})
        await asyncio.sleep(1)
    # Client will keep connection; server closes when handler returns


async def index(request: web.Request) -> web.Response:
    html = """
    <!doctype html>
    <meta charset="utf-8">
    <title>aoihttp SSE basic</title>
    <body>
        <h1>SSE basic demo</h1>
        <pre id="log"></pre>
        <script>
            const log = document.getElementById('log');
            const es = new EventSource('/sse');
            es.onmessage = (ev) => {
              log.textContent += ev.data + "\n";
            };
        </script>
    </body>
    """
    return web.Response(text=html, content_type="text/html")


def main() -> None:
    app = web.Application()
    app.router.add_get("/", index)
    app.router.add_get("/sse", stream_numbers)
    web.run_app(app, port=8080)


if __name__ == "__main__":
    main()

