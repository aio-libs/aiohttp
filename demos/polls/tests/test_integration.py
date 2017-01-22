"""
Integration tests. They need a running database.

Beware, they destroy your db using sudo.
"""


async def test_index(cli, app_db):
    response = await cli.get('/poll/1')
    assert response.status == 200
    assert 'What\'s new?' in await response.text()


async def test_results(cli, app_db):
    response = await cli.get('/poll/1/results')
    assert response.status == 200
    assert 'Just hacking again' in await response.text()
