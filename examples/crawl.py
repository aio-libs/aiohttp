#!/usr/bin/env python3

import logging
import re
import signal
import sys
import tulip
import urllib.parse

import asynchttp


class Crawler:

    def __init__(self, rooturl, loop, maxtasks=100):
        self.rooturl = rooturl
        self.loop = loop
        self.todo = set()
        self.busy = set()
        self.done = {}
        self.tasks = set()
        self.sem = tulip.Semaphore(maxtasks)

        # session stores cookies between requests and uses connection pool
        self.session = asynchttp.Session()

    @tulip.coroutine
    def run(self):
        tulip.Task(self.addurls([(self.rooturl, '')]))  # Set initial work.
        yield from tulip.sleep(1)
        while self.busy:
            yield from tulip.sleep(1)

        self.session.close()
        self.loop.stop()

    @tulip.coroutine
    def addurls(self, urls):
        for url, parenturl in urls:
            url = urllib.parse.urljoin(parenturl, url)
            url, frag = urllib.parse.urldefrag(url)
            if (url.startswith(self.rooturl) and
                    url not in self.busy and
                    url not in self.done and
                    url not in self.todo):
                self.todo.add(url)
                yield from self.sem.acquire()
                task = tulip.Task(self.process(url))
                task.add_done_callback(lambda t: self.sem.release())
                task.add_done_callback(self.tasks.remove)
                self.tasks.add(task)

    @tulip.coroutine
    def process(self, url):
        print('processing:', url)

        self.todo.remove(url)
        self.busy.add(url)
        try:
            resp = yield from asynchttp.request(
                'get', url, session=self.session)
        except Exception as exc:
            print('...', url, 'has error', repr(str(exc)))
            self.done[url] = False
        else:
            if resp.status == 200 and resp.get_content_type() == 'text/html':
                data = (yield from resp.read()).decode('utf-8', 'replace')
                urls = re.findall(r'(?i)href=["\']?([^\s"\'<>]+)', data)
                tulip.Task(self.addurls([(u, url) for u in urls]))

            resp.close()
            self.done[url] = True

        self.busy.remove(url)
        print(len(self.done), 'completed tasks,', len(self.tasks),
              'still pending, todo', len(self.todo))


def main():
    loop = tulip.get_event_loop()

    c = Crawler(sys.argv[1], loop)
    tulip.Task(c.run())

    try:
        loop.add_signal_handler(signal.SIGINT, loop.stop)
    except RuntimeError:
        pass
    loop.run_forever()
    print('todo:', len(c.todo))
    print('busy:', len(c.busy))
    print('done:', len(c.done), '; ok:', sum(c.done.values()))
    print('tasks:', len(c.tasks))


if __name__ == '__main__':
    if '--iocp' in sys.argv:
        from tulip import events, windows_events
        sys.argv.remove('--iocp')
        logging.info('using iocp')
        el = windows_events.ProactorEventLoop()
        events.set_event_loop(el)

    main()
