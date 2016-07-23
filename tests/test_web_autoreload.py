import subprocess
import sys
import atexit
import time
import urllib.request

from conftest import chdir_context

def test_autoreload_simple(unused_port, tmpdir):
    port = unused_port
    host = '127.0.0.1'
    url = 'http://{}:{}'.format(host, port)

    import autoreloadapp

    def wait_value(v):
        for i in range(100):
            try:
                r = urllib.request.urlopen(url).read()
                if r == v:
                    break
            except urllib.error.URLError:
                pass
            time.sleep(0.03)
        assert urllib.request.urlopen(url).read() == v

    FILE = 'watchfile.py'

    with chdir_context(str(tmpdir)):
        with open(FILE, 'wt') as f:
            f.write('a = b"0"')
        p = subprocess.Popen([sys.executable, autoreloadapp.__file__, host, str(port)], stdout=sys.stdout, stderr=subprocess.STDOUT)
        atexit.register(lambda p=p: (p.kill(), p.wait()))

        wait_value(b'0')
        time.sleep(1)
        with open(FILE, 'wt') as f:
            f.write('a = b"1"')
        wait_value(b'1')
