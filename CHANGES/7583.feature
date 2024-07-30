Implemented filter_cookies() with domain-matching and path-matching on the keys, instead of testing every single cookie.
This may break existing cookies that have been saved with `CookieJar.save()`. Cookies can be migrated with this script::

    import pickle
    with file_path.open("rb") as f:
        cookies = pickle.load(f)

    morsels = [(name, m) for c in cookies.values() for name, m in c.items()]
    cookies.clear()
    for name, m in morsels:
        cookies[(m["domain"], m["path"].rstrip("/"))][name] = m

    with file_path.open("wb") as f:
        pickle.dump(cookies, f, pickle.HIGHEST_PROTOCOL)
