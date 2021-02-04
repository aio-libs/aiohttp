AioHTTPTestCase is more async friendly now.

For people who use unittest and are used to use unittest.TestCase
it will be easier to write new test cases like the sync version of the TestCase class,
without using the decorator `@unittest_run_loop`, just `async def test_*`.
The only difference is that for the people using python3.7 and below a new dependency is needed, it is `asynctestcase`.
