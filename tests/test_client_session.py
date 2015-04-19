# -*- coding: utf-8 -*-
"""Tests for aiohttp/client.py"""

import asyncio
import unittest
import unittest.mock

import aiohttp
from aiohttp.client import ClientSession
from aiohttp.multidict import MultiDict, CIMultiDict


class ClientResponseTests(unittest.TestCase):

    maxDiff = None

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.run = self.loop.run_until_complete

    def tearDown(self):
        self.loop.close()

    def test_init_headers_simple_dict(self):
        session = ClientSession(
            headers={
                "h1": "header1",
                "h2": "header2"
            }, loop=self.loop)
        self.assertEqual(
            set(session._default_headers),
            set([("h1", "header1"),
                 ("h2", "header2")]))

    def test_init_headers_list_of_tuples(self):
        session = ClientSession(
            headers=[("h1", "header1"),
                     ("h2", "header2"),
                     ("h3", "header3")],
            loop=self.loop)
        self.assertEqual(
            set(session._default_headers),
            set([("h1", "header1"),
                 ("h2", "header2"),
                 ("h3", "header3")]))

    def test_init_headers_MultiDict(self):
        session = ClientSession(
            headers=MultiDict(
                [("h1", "header1"),
                 ("h2", "header2"),
                 ("h3", "header3")]),
            loop=self.loop)
        self.assertEqual(
            set(session._default_headers),
            set([("h1", "header1"),
                 ("h2", "header2"),
                 ("h3", "header3")]))

    def test_init_cookies_with_simple_dict(self):
        session = ClientSession(
            cookies={
                "c1": "cookie1",
                "c2": "cookie2"
            }, loop=self.loop)
        self.assertEqual(set(session.cookies), {'c1', 'c2'})
        self.assertEqual(session.cookies['c1'].value, 'cookie1')
        self.assertEqual(session.cookies['c2'].value, 'cookie2')

    def test_init_cookies_with_list_of_tuples(self):
        session = ClientSession(
            cookies=[("c1", "cookie1"),
                     ("c2", "cookie2")],
            loop=self.loop)
        self.assertEqual(set(session.cookies), {'c1', 'c2'})
        self.assertEqual(session.cookies['c1'].value, 'cookie1')
        self.assertEqual(session.cookies['c2'].value, 'cookie2')

    def test_merge_headers(self):
        # Check incoming simple dict
        session = ClientSession(
            headers={
                "h1": "header1",
                "h2": "header2"
            }, loop=self.loop)
        headers = session._prepare_headers({
            "h1": "h1"
        })
        self.assertIsInstance(headers, CIMultiDict)
        self.assertEqual(headers, CIMultiDict([
            ("h1", "h1"),
            ("h2", "header2")
        ]))

    def test_merge_headers_with_multi_dict(self):
        session = ClientSession(
            headers={
                "h1": "header1",
                "h2": "header2"
            }, loop=self.loop)
        headers = session._prepare_headers(MultiDict([("h1", "h1")]))
        self.assertIsInstance(headers, CIMultiDict)
        self.assertEqual(headers, CIMultiDict([
            ("h1", "h1"),
            ("h2", "header2")
        ]))

    def test_merge_headers_with_list_of_tuples(self):
        session = ClientSession(
            headers={
                "h1": "header1",
                "h2": "header2"
            }, loop=self.loop)
        headers = session._prepare_headers([("h1", "h1")])
        self.assertIsInstance(headers, CIMultiDict)
        self.assertEqual(headers, CIMultiDict([
            ("h1", "h1"),
            ("h2", "header2")
        ]))

    def _make_one(self):
        session = ClientSession(loop=self.loop)
        params = dict(
            headers={"Authorization": "Basic ..."},
            max_redirects=2,
            encoding="latin1",
            version=aiohttp.HttpVersion10,
            compress="deflate",
            chunked=True,
            expect100=True,
            read_until_eof=False)
        return session, params

    @unittest.mock.patch("aiohttp.client.ClientSession.request")
    def test_http_GET(self, patched):
        session, params = self._make_one()
        self.run(session.get(
            "http://test.example.com",
            params={"x": 1},
            **params))
        self.assertTrue(patched.called, "`ClientSession.request` not called")
        self.assertEqual(
            list(patched.call_args),
            [("GET", "http://test.example.com",),
             dict(
                 params={"x": 1},
                 allow_redirects=True,
                 **params)])

    @unittest.mock.patch("aiohttp.client.ClientSession.request")
    def test_http_OPTIONS(self, patched):
        session, params = self._make_one()
        self.run(session.options(
            "http://opt.example.com",
            params={"x": 2},
            **params))
        self.assertTrue(patched.called, "`ClientSession.request` not called")
        self.assertEqual(
            list(patched.call_args),
            [("OPTIONS", "http://opt.example.com",),
             dict(
                params={"x": 2},
                allow_redirects=True,
                **params)])

    @unittest.mock.patch("aiohttp.client.ClientSession.request")
    def test_http_HEAD(self, patched):
        session, params = self._make_one()
        self.run(session.head(
            "http://head.example.com",
            params={"x": 2},
            **params))
        self.assertTrue(patched.called, "`ClientSession.request` not called")
        self.assertEqual(
            list(patched.call_args),
            [("HEAD", "http://head.example.com",),
             dict(
                params={"x": 2},
                allow_redirects=False,
                **params)])

    @unittest.mock.patch("aiohttp.client.ClientSession.request")
    def test_http_POST(self, patched):
        session, params = self._make_one()
        self.run(session.post(
            "http://post.example.com",
            params={"x": 2},
            data="Some_data",
            files={"x": '1'},
            **params))
        self.assertTrue(patched.called, "`ClientSession.request` not called")
        self.assertEqual(
            list(patched.call_args),
            [("POST", "http://post.example.com",),
             dict(
                params={"x": 2},
                data="Some_data",
                files={"x": '1'},
                **params)])

    @unittest.mock.patch("aiohttp.client.ClientSession.request")
    def test_http_PUT(self, patched):
        session, params = self._make_one()
        self.run(session.put(
            "http://put.example.com",
            params={"x": 2},
            data="Some_data",
            files={"x": '1'},
            **params))
        self.assertTrue(patched.called, "`ClientSession.request` not called")
        self.assertEqual(
            list(patched.call_args),
            [("PUT", "http://put.example.com",),
             dict(
                 params={"x": 2},
                 data="Some_data",
                 files={"x": '1'},
                 **params)])

    @unittest.mock.patch("aiohttp.client.ClientSession.request")
    def test_http_PATCH(self, patched):
        session, params = self._make_one()
        self.run(session.patch(
            "http://patch.example.com",
            params={"x": 2},
            data="Some_data",
            files={"x": '1'},
            **params))
        self.assertTrue(patched.called, "`ClientSession.request` not called")
        self.assertEqual(
            list(patched.call_args),
            [("PATCH", "http://patch.example.com",),
             dict(
                params={"x": 2},
                data="Some_data",
                files={"x": '1'},
                **params)])

    @unittest.mock.patch("aiohttp.client.ClientSession.request")
    def test_http_DELETE(self, patched):
        session, params = self._make_one()
        self.run(session.delete(
            "http://delete.example.com",
            params={"x": 2},
            **params))
        self.assertTrue(patched.called, "`ClientSession.request` not called")
        self.assertEqual(
            list(patched.call_args),
            [("DELETE", "http://delete.example.com",),
             dict(
                params={"x": 2},
                **params)])
