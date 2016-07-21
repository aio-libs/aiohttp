from .views import index, poll, results, vote


def setup_routes(app, project_root):
    app.router.add_route('GET', '/', index)
    app.router.add_route('GET', '/poll/{question_id}', poll, name='poll')
    app.router.add_route('GET', '/poll/{question_id}/results',
                         results, name='results')
    app.router.add_route('POST', '/poll/{question_id}/vote', vote, name='vote')
    app.router.add_static('/static/',
                          path=str(project_root / 'static'),
                          name='static')
