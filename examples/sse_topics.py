import asyncio

from aiohttp import web
from aiohttp.sse import sse_response

TOPICS = ("news", "sports", "tech")


async def sse_topics_handler(request: web.Request) -> web.StreamResponse:
    topic = request.query.get("topic")
    async with sse_response(request, heartbeat=10, json=True) as resp:
        # Periodically send messages across topics, client filters by topic
        for i in range(20):
            t = TOPICS[i % len(TOPICS)]
            payload = {"seq": i, "topic": t, "message": f"update-{i}"}
            await resp.send(payload, event="update", topic=t)
            await asyncio.sleep(0.5)
        return resp


async def index(request: web.Request) -> web.Response:
    html = """
    <!doctype html>
    <meta charset="utf-8">
    <title>aoihttp SSE topics</title>
    <body>
        <h1>SSE topics demo</h1>
        <label>Topic: <input id="topic" value="news"></label>
        <button id="start">Start</button>
        <pre id="log"></pre>
        <script>
            const log = document.getElementById('log');
            document.getElementById('start').onclick = () => {
                const t = document.getElementById('topic').value;
                const es = new EventSource(`/sse?topic=${encodeURIComponent(t)}`);
                es.addEventListener('update', (ev) => {
                  const obj = JSON.parse(ev.data);
                  if (obj.topic === t) {
                    log.textContent += ev.data + "\n";
                  }
                });
            };
        </script>
    </body>
    """
    return web.Response(text=html, content_type="text/html")


def main() -> None:
    app = web.Application()
    app.router.add_get("/", index)
    app.router.add_get("/sse", sse_topics_handler)
    web.run_app(app, port=8081)


if __name__ == "__main__":
    main()
