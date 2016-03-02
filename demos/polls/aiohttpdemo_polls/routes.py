
def setup_routes(app, handler, project_root):
    add_route = app.router.add_route
    add_route('GET', '/', handler.index)
    add_route('GET', '/poll/{question_id}', handler.poll, name='poll')
    add_route('GET', '/poll/{question_id}/results',
              handler.results, name='results')
    add_route('POST', '/poll/{question_id}/vote', handler.vote, name='vote')
    app.router.add_static('/static/',
                          path=str(project_root / 'static'),
                          name='static')
