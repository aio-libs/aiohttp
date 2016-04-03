.. _tutorial-templates:

Templates
=========

Let's add more useful views: ::

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
ping