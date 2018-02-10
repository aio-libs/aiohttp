import pytest

import aiohttp
from aiohttp import content_disposition_filename, parse_content_disposition


class TestParseContentDisposition:
    # http://greenbytes.de/tech/tc2231/

    def test_parse_empty(self):
        disptype, params = parse_content_disposition(None)
        assert disptype is None
        assert {} == params

    def test_inlonly(self):
        disptype, params = parse_content_disposition('inline')
        assert 'inline' == disptype
        assert {} == params

    def test_inlonlyquoted(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition('"inline"')
        assert disptype is None
        assert {} == params

    def test_semicolon(self):
        disptype, params = parse_content_disposition(
            'form-data; name="data"; filename="file ; name.mp4"')
        assert disptype == 'form-data'
        assert params == {'name': 'data', 'filename': 'file ; name.mp4'}

    def test_inlwithasciifilename(self):
        disptype, params = parse_content_disposition(
            'inline; filename="foo.html"')
        assert 'inline' == disptype
        assert {'filename': 'foo.html'} == params

    def test_inlwithfnattach(self):
        disptype, params = parse_content_disposition(
            'inline; filename="Not an attachment!"')
        assert 'inline' == disptype
        assert {'filename': 'Not an attachment!'} == params

    def test_attonly(self):
        disptype, params = parse_content_disposition('attachment')
        assert 'attachment' == disptype
        assert {} == params

    def test_attonlyquoted(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition('"attachment"')
        assert disptype is None
        assert {} == params

    def test_attonlyucase(self):
        disptype, params = parse_content_disposition('ATTACHMENT')
        assert 'attachment' == disptype
        assert {} == params

    def test_attwithasciifilename(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="foo.html"')
        assert 'attachment' == disptype
        assert {'filename': 'foo.html'} == params

    def test_inlwithasciifilenamepdf(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="foo.pdf"')
        assert 'attachment' == disptype
        assert {'filename': 'foo.pdf'} == params

    def test_attwithasciifilename25(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="0000000000111111111122222"')
        assert 'attachment' == disptype
        assert {'filename': '0000000000111111111122222'} == params

    def test_attwithasciifilename35(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="00000000001111111111222222222233333"')
        assert 'attachment' == disptype
        assert {'filename': '00000000001111111111222222222233333'} == params

    def test_attwithasciifnescapedchar(self):
        disptype, params = parse_content_disposition(
            r'attachment; filename="f\oo.html"')
        assert 'attachment' == disptype
        assert {'filename': 'foo.html'} == params

    def test_attwithasciifnescapedquote(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="\"quoting\" tested.html"')
        assert 'attachment' == disptype
        assert {'filename': '"quoting" tested.html'} == params

    @pytest.mark.skip('need more smart parser which respects quoted text')
    def test_attwithquotedsemicolon(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="Here\'s a semicolon;.html"')
        assert 'attachment' == disptype
        assert {'filename': 'Here\'s a semicolon;.html'} == params

    def test_attwithfilenameandextparam(self):
        disptype, params = parse_content_disposition(
            'attachment; foo="bar"; filename="foo.html"')
        assert 'attachment' == disptype
        assert {'filename': 'foo.html', 'foo': 'bar'} == params

    def test_attwithfilenameandextparamescaped(self):
        disptype, params = parse_content_disposition(
            'attachment; foo="\"\\";filename="foo.html"')
        assert 'attachment' == disptype
        assert {'filename': 'foo.html', 'foo': '"\\'} == params

    def test_attwithasciifilenameucase(self):
        disptype, params = parse_content_disposition(
            'attachment; FILENAME="foo.html"')
        assert 'attachment' == disptype
        assert {'filename': 'foo.html'} == params

    def test_attwithasciifilenamenq(self):
        disptype, params = parse_content_disposition(
            'attachment; filename=foo.html')
        assert 'attachment' == disptype
        assert {'filename': 'foo.html'} == params

    def test_attwithtokfncommanq(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; filename=foo,bar.html')
        assert disptype is None
        assert {} == params

    def test_attwithasciifilenamenqs(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; filename=foo.html ;')
        assert disptype is None
        assert {} == params

    def test_attemptyparam(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; ;filename=foo')
        assert disptype is None
        assert {} == params

    def test_attwithasciifilenamenqws(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; filename=foo bar.html')
        assert disptype is None
        assert {} == params

    def test_attwithfntokensq(self):
        disptype, params = parse_content_disposition(
            "attachment; filename='foo.html'")
        assert 'attachment' == disptype
        assert {'filename': "'foo.html'"} == params

    def test_attwithisofnplain(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="foo-ä.html"')
        assert 'attachment' == disptype
        assert {'filename': 'foo-ä.html'} == params

    def test_attwithutf8fnplain(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="foo-Ã¤.html"')
        assert 'attachment' == disptype
        assert {'filename': 'foo-Ã¤.html'} == params

    def test_attwithfnrawpctenca(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="foo-%41.html"')
        assert 'attachment' == disptype
        assert {'filename': 'foo-%41.html'} == params

    def test_attwithfnusingpct(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="50%.html"')
        assert 'attachment' == disptype
        assert {'filename': '50%.html'} == params

    def test_attwithfnrawpctencaq(self):
        disptype, params = parse_content_disposition(
            r'attachment; filename="foo-%\41.html"')
        assert 'attachment' == disptype
        assert {'filename': r'foo-%41.html'} == params

    def test_attwithnamepct(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="foo-%41.html"')
        assert 'attachment' == disptype
        assert {'filename': 'foo-%41.html'} == params

    def test_attwithfilenamepctandiso(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="ä-%41.html"')
        assert 'attachment' == disptype
        assert {'filename': 'ä-%41.html'} == params

    def test_attwithfnrawpctenclong(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="foo-%c3%a4-%e2%82%ac.html"')
        assert 'attachment' == disptype
        assert {'filename': 'foo-%c3%a4-%e2%82%ac.html'} == params

    def test_attwithasciifilenamews1(self):
        disptype, params = parse_content_disposition(
            'attachment; filename ="foo.html"')
        assert 'attachment' == disptype
        assert {'filename': 'foo.html'} == params

    def test_attwith2filenames(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; filename="foo.html"; filename="bar.html"')
        assert disptype is None
        assert {} == params

    def test_attfnbrokentoken(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; filename=foo[1](2).html')
        assert disptype is None
        assert {} == params

    def test_attfnbrokentokeniso(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; filename=foo-ä.html')
        assert disptype is None
        assert {} == params

    def test_attfnbrokentokenutf(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; filename=foo-Ã¤.html')
        assert disptype is None
        assert {} == params

    def test_attmissingdisposition(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'filename=foo.html')
        assert disptype is None
        assert {} == params

    def test_attmissingdisposition2(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'x=y; filename=foo.html')
        assert disptype is None
        assert {} == params

    def test_attmissingdisposition3(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                '"foo; filename=bar;baz"; filename=qux')
        assert disptype is None
        assert {} == params

    def test_attmissingdisposition4(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'filename=foo.html, filename=bar.html')
        assert disptype is None
        assert {} == params

    def test_emptydisposition(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                '; filename=foo.html')
        assert disptype is None
        assert {} == params

    def test_doublecolon(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                ': inline; attachment; filename=foo.html')
        assert disptype is None
        assert {} == params

    def test_attandinline(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'inline; attachment; filename=foo.html')
        assert disptype is None
        assert {} == params

    def test_attandinline2(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; inline; filename=foo.html')
        assert disptype is None
        assert {} == params

    def test_attbrokenquotedfn(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; filename="foo.html".txt')
        assert disptype is None
        assert {} == params

    def test_attbrokenquotedfn2(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; filename="bar')
        assert disptype is None
        assert {} == params

    def test_attbrokenquotedfn3(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; filename=foo"bar;baz"qux')
        assert disptype is None
        assert {} == params

    def test_attmultinstances(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; filename=foo.html, attachment; filename=bar.html')
        assert disptype is None
        assert {} == params

    def test_attmissingdelim(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; foo=foo filename=bar')
        assert disptype is None
        assert {} == params

    def test_attmissingdelim2(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; filename=bar foo=foo')
        assert disptype is None
        assert {} == params

    def test_attmissingdelim3(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment filename=bar')
        assert disptype is None
        assert {} == params

    def test_attreversed(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'filename=foo.html; attachment')
        assert disptype is None
        assert {} == params

    def test_attconfusedparam(self):
        disptype, params = parse_content_disposition(
            'attachment; xfilename=foo.html')
        assert 'attachment' == disptype
        assert {'xfilename': 'foo.html'} == params

    def test_attabspath(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="/foo.html"')
        assert 'attachment' == disptype
        assert {'filename': 'foo.html'} == params

    def test_attabspathwin(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="\\foo.html"')
        assert 'attachment' == disptype
        assert {'filename': 'foo.html'} == params

    def test_attcdate(self):
        disptype, params = parse_content_disposition(
            'attachment; creation-date="Wed, 12 Feb 1997 16:29:51 -0500"')
        assert 'attachment' == disptype
        assert {'creation-date': 'Wed, 12 Feb 1997 16:29:51 -0500'} == params

    def test_attmdate(self):
        disptype, params = parse_content_disposition(
            'attachment; modification-date="Wed, 12 Feb 1997 16:29:51 -0500"')
        assert 'attachment' == disptype
        assert {'modification-date':
                'Wed, 12 Feb 1997 16:29:51 -0500'} == params

    def test_dispext(self):
        disptype, params = parse_content_disposition('foobar')
        assert 'foobar' == disptype
        assert {} == params

    def test_dispextbadfn(self):
        disptype, params = parse_content_disposition(
            'attachment; example="filename=example.txt"')
        assert 'attachment' == disptype
        assert {'example': 'filename=example.txt'} == params

    def test_attwithisofn2231iso(self):
        disptype, params = parse_content_disposition(
            "attachment; filename*=iso-8859-1''foo-%E4.html")
        assert 'attachment' == disptype
        assert {'filename*': 'foo-ä.html'} == params

    def test_attwithfn2231utf8(self):
        disptype, params = parse_content_disposition(
            "attachment; filename*=UTF-8''foo-%c3%a4-%e2%82%ac.html")
        assert 'attachment' == disptype
        assert {'filename*': 'foo-ä-€.html'} == params

    def test_attwithfn2231noc(self):
        disptype, params = parse_content_disposition(
            "attachment; filename*=''foo-%c3%a4-%e2%82%ac.html")
        assert 'attachment' == disptype
        assert {'filename*': 'foo-ä-€.html'} == params

    def test_attwithfn2231utf8comp(self):
        disptype, params = parse_content_disposition(
            "attachment; filename*=UTF-8''foo-a%cc%88.html")
        assert 'attachment' == disptype
        assert {'filename*': 'foo-ä.html'} == params

    @pytest.mark.skip('should raise decoding error: %82 is invalid for latin1')
    def test_attwithfn2231utf8_bad(self):
        with pytest.warns(aiohttp.BadContentDispositionParam):
            disptype, params = parse_content_disposition(
                "attachment; filename*=iso-8859-1''foo-%c3%a4-%e2%82%ac.html")
        assert 'attachment' == disptype
        assert {} == params

    @pytest.mark.skip('should raise decoding error: %E4 is invalid for utf-8')
    def test_attwithfn2231iso_bad(self):
        with pytest.warns(aiohttp.BadContentDispositionParam):
            disptype, params = parse_content_disposition(
                "attachment; filename*=utf-8''foo-%E4.html")
        assert 'attachment' == disptype
        assert {} == params

    def test_attwithfn2231ws1(self):
        with pytest.warns(aiohttp.BadContentDispositionParam):
            disptype, params = parse_content_disposition(
                "attachment; filename *=UTF-8''foo-%c3%a4.html")
        assert 'attachment' == disptype
        assert {} == params

    def test_attwithfn2231ws2(self):
        disptype, params = parse_content_disposition(
            "attachment; filename*= UTF-8''foo-%c3%a4.html")
        assert 'attachment' == disptype
        assert {'filename*': 'foo-ä.html'} == params

    def test_attwithfn2231ws3(self):
        disptype, params = parse_content_disposition(
            "attachment; filename* =UTF-8''foo-%c3%a4.html")
        assert 'attachment' == disptype
        assert {'filename*': 'foo-ä.html'} == params

    def test_attwithfn2231quot(self):
        with pytest.warns(aiohttp.BadContentDispositionParam):
            disptype, params = parse_content_disposition(
                "attachment; filename*=\"UTF-8''foo-%c3%a4.html\"")
        assert 'attachment' == disptype
        assert {} == params

    def test_attwithfn2231quot2(self):
        with pytest.warns(aiohttp.BadContentDispositionParam):
            disptype, params = parse_content_disposition(
                "attachment; filename*=\"foo%20bar.html\"")
        assert 'attachment' == disptype
        assert {} == params

    def test_attwithfn2231singleqmissing(self):
        with pytest.warns(aiohttp.BadContentDispositionParam):
            disptype, params = parse_content_disposition(
                "attachment; filename*=UTF-8'foo-%c3%a4.html")
        assert 'attachment' == disptype
        assert {} == params

    @pytest.mark.skip('urllib.parse.unquote is tolerate to standalone % chars')
    def test_attwithfn2231nbadpct1(self):
        with pytest.warns(aiohttp.BadContentDispositionParam):
            disptype, params = parse_content_disposition(
                "attachment; filename*=UTF-8''foo%")
        assert 'attachment' == disptype
        assert {} == params

    @pytest.mark.skip('urllib.parse.unquote is tolerate to standalone % chars')
    def test_attwithfn2231nbadpct2(self):
        with pytest.warns(aiohttp.BadContentDispositionParam):
            disptype, params = parse_content_disposition(
                "attachment; filename*=UTF-8''f%oo.html")
        assert 'attachment' == disptype
        assert {} == params

    def test_attwithfn2231dpct(self):
        disptype, params = parse_content_disposition(
            "attachment; filename*=UTF-8''A-%2541.html")
        assert 'attachment' == disptype
        assert {'filename*': 'A-%41.html'} == params

    def test_attwithfn2231abspathdisguised(self):
        disptype, params = parse_content_disposition(
            "attachment; filename*=UTF-8''%5cfoo.html")
        assert 'attachment' == disptype
        assert {'filename*': '\\foo.html'} == params

    def test_attfncont(self):
        disptype, params = parse_content_disposition(
            'attachment; filename*0="foo."; filename*1="html"')
        assert 'attachment' == disptype
        assert {'filename*0': 'foo.',
                'filename*1': 'html'} == params

    def test_attfncontqs(self):
        disptype, params = parse_content_disposition(
            r'attachment; filename*0="foo"; filename*1="\b\a\r.html"')
        assert 'attachment' == disptype
        assert {'filename*0': 'foo',
                'filename*1': 'bar.html'} == params

    def test_attfncontenc(self):
        disptype, params = parse_content_disposition(
            'attachment; filename*0*=UTF-8''foo-%c3%a4; filename*1=".html"')
        assert 'attachment' == disptype
        assert {'filename*0*': 'UTF-8''foo-%c3%a4',
                'filename*1': '.html'} == params

    def test_attfncontlz(self):
        disptype, params = parse_content_disposition(
            'attachment; filename*0="foo"; filename*01="bar"')
        assert 'attachment' == disptype
        assert {'filename*0': 'foo',
                'filename*01': 'bar'} == params

    def test_attfncontnc(self):
        disptype, params = parse_content_disposition(
            'attachment; filename*0="foo"; filename*2="bar"')
        assert 'attachment' == disptype
        assert {'filename*0': 'foo',
                'filename*2': 'bar'} == params

    def test_attfnconts1(self):
        disptype, params = parse_content_disposition(
            'attachment; filename*0="foo."; filename*2="html"')
        assert 'attachment' == disptype
        assert {'filename*0': 'foo.',
                'filename*2': 'html'} == params

    def test_attfncontord(self):
        disptype, params = parse_content_disposition(
            'attachment; filename*1="bar"; filename*0="foo"')
        assert 'attachment' == disptype
        assert {'filename*0': 'foo',
                'filename*1': 'bar'} == params

    def test_attfnboth(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="foo-ae.html";'
            " filename*=UTF-8''foo-%c3%a4.html")
        assert 'attachment' == disptype
        assert {'filename': 'foo-ae.html',
                'filename*': 'foo-ä.html'} == params

    def test_attfnboth2(self):
        disptype, params = parse_content_disposition(
            "attachment; filename*=UTF-8''foo-%c3%a4.html;"
            ' filename="foo-ae.html"')
        assert 'attachment' == disptype
        assert {'filename': 'foo-ae.html',
                'filename*': 'foo-ä.html'} == params

    def test_attfnboth3(self):
        disptype, params = parse_content_disposition(
            "attachment; filename*0*=ISO-8859-15''euro-sign%3d%a4;"
            " filename*=ISO-8859-1''currency-sign%3d%a4")
        assert 'attachment' == disptype
        assert {'filename*': 'currency-sign=¤',
                'filename*0*': "ISO-8859-15''euro-sign%3d%a4"} == params

    def test_attnewandfn(self):
        disptype, params = parse_content_disposition(
            'attachment; foobar=x; filename="foo.html"')
        assert 'attachment' == disptype
        assert {'foobar': 'x',
                'filename': 'foo.html'} == params

    def test_attrfc2047token(self):
        with pytest.warns(aiohttp.BadContentDispositionHeader):
            disptype, params = parse_content_disposition(
                'attachment; filename==?ISO-8859-1?Q?foo-=E4.html?=')
        assert disptype is None
        assert {} == params

    def test_attrfc2047quoted(self):
        disptype, params = parse_content_disposition(
            'attachment; filename="=?ISO-8859-1?Q?foo-=E4.html?="')
        assert 'attachment' == disptype
        assert {'filename': '=?ISO-8859-1?Q?foo-=E4.html?='} == params

    def test_bad_continuous_param(self):
        with pytest.warns(aiohttp.BadContentDispositionParam):
            disptype, params = parse_content_disposition(
                'attachment; filename*0=foo bar')
        assert 'attachment' == disptype
        assert {} == params


class TestContentDispositionFilename:
    # http://greenbytes.de/tech/tc2231/

    def test_no_filename(self):
        assert content_disposition_filename({}) is None
        assert content_disposition_filename({'foo': 'bar'}) is None

    def test_filename(self):
        params = {'filename': 'foo.html'}
        assert 'foo.html' == content_disposition_filename(params)

    def test_filename_ext(self):
        params = {'filename*': 'файл.html'}
        assert 'файл.html' == content_disposition_filename(params)

    def test_attfncont(self):
        params = {'filename*0': 'foo.', 'filename*1': 'html'}
        assert 'foo.html' == content_disposition_filename(params)

    def test_attfncontqs(self):
        params = {'filename*0': 'foo', 'filename*1': 'bar.html'}
        assert 'foobar.html' == content_disposition_filename(params)

    def test_attfncontenc(self):
        params = {'filename*0*': "UTF-8''foo-%c3%a4",
                  'filename*1': '.html'}
        assert 'foo-ä.html' == content_disposition_filename(params)

    def test_attfncontlz(self):
        params = {'filename*0': 'foo',
                  'filename*01': 'bar'}
        assert 'foo' == content_disposition_filename(params)

    def test_attfncontnc(self):
        params = {'filename*0': 'foo',
                  'filename*2': 'bar'}
        assert 'foo' == content_disposition_filename(params)

    def test_attfnconts1(self):
        params = {'filename*1': 'foo',
                  'filename*2': 'bar'}
        assert content_disposition_filename(params) is None

    def test_attfnboth(self):
        params = {'filename': 'foo-ae.html',
                  'filename*': 'foo-ä.html'}
        assert 'foo-ä.html' == content_disposition_filename(params)

    def test_attfnboth3(self):
        params = {'filename*0*': "ISO-8859-15''euro-sign%3d%a4",
                  'filename*': 'currency-sign=¤'}
        assert 'currency-sign=¤' == content_disposition_filename(params)

    def test_attrfc2047quoted(self):
        params = {'filename': '=?ISO-8859-1?Q?foo-=E4.html?='}
        assert '=?ISO-8859-1?Q?foo-=E4.html?=' == content_disposition_filename(
            params)
