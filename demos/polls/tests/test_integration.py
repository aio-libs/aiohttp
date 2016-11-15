"""
Integration tests. They need a running database.

Beware, they destroy your db using sudo.
"""


async def _test_index(create_app):
    app, url, client_session = await create_app()
    async with client_session.get('{}/'.format(url)) as response:
        assert response.status == 200, await response.text()


def test_index(create_app, event_loop, app_db):
    event_loop.run_until_complete(_test_index(create_app))


async def _test_results(create_app):
    app, url, client_session = await create_app()
    async with client_session.get('{}/results'.format(url)) as response:
        assert response.status == 200, await response.text()


def test_results(create_app, event_loop, app_db):
    event_loop.run_until_complete(_test_results(create_app))
