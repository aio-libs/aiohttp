import aiohttp_jinja2
from aiohttp import web
from . import db


class SiteHandler:

    def __init__(self, pg):
        self.postgres = pg

    @aiohttp_jinja2.template('index.html')
    async def index(self, request):
        async with self.postgres.acquire() as conn:
            cursor = await conn.execute(db.question.select())
            records = await cursor.fetchall()
        questions = [dict(q) for q in records]
        return {'questions': questions}

    @aiohttp_jinja2.template('detail.html')
    async def poll(self, request):
        question_id = request.match_info['question_id']
        try:
            question, choices = await db.get_question(self.postgres,
                                                      question_id)
        except db.RecordNotFound as e:
            raise web.HTTPNotFound(text=str(e))
        return {
            'question': question,
            'choices': choices
        }

    @aiohttp_jinja2.template('results.html')
    async def results(self, request):
        question_id = request.match_info['question_id']

        try:
            question, choices = await db.get_question(self.postgres,
                                                      question_id)
        except db.RecordNotFound as e:
            raise web.HTTPNotFound(text=str(e))

        return {
            'question': question,
            'choices': choices
        }

    async def vote(self, request):
        question_id = int(request.match_info['question_id'])
        data = await request.post()
        try:
            choice_id = int(data['choice'])
        except (KeyError, TypeError, ValueError) as e:
            raise web.HTTPBadRequest(
                text='You have not specified choice value') from e
        try:
            await db.vote(self.postgres, question_id, choice_id)
        except db.RecordNotFound as e:
            raise web.HTTPNotFound(text=str(e))
        router = request.app.router
        url = router['results'].url(parts={'question_id': question_id})
        return web.HTTPFound(location=url)
