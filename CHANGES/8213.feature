Provided users with a new option to use loop.sendfile when uploading files.
like 

async with aiohttp.ClientSession() as sess:
        data = aiohttp.FormData(quote_fields=False)
        assert pathlib.Path(__file__).exists()
        data.add_field('file', payload.SendFile(__file__), filename=pathlib.Path(__file__).name)
        async with sess.post('http://localhost:8080/upload', data=data) as resp:
            with open(pathlib.Path(__file__), "rb") as fp:
                assert fp.read() == await resp.read()
                print("Success")

 -- by :user:`junbaibai0719`