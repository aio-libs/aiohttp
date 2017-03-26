from aiohttp import web


app_test = web.Application()


@app_test.route('/index.html')
def get(req):
    pass
