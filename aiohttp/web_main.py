from . import web
from argparse import ArgumentParser
from importlib import import_module


def main():
    arg_parser = ArgumentParser(
        description="aiohttp.web TCP/IP Application server",
        prog="aiohttp.web"
    )
    arg_parser.add_argument(
        "entry_func",
        help=("Callable returning the `aiohttp.web.Application` instance to "
              "run. Should be specified in the Python import syntax, "
              "e.g. 'package.module.function')"),
        metavar="entry-func"
    )
    arg_parser.add_argument(
        "-n", "--hostname",
        help="TCP/IP hostname to serve on (default: %(default)r)",
        default="localhost"
    )
    arg_parser.add_argument(
        "-p", "--port",
        help="TCP/IP port to serve on (default: %(default)r)",
        type=int,
        default="8080"
    )
    args, extra_args = arg_parser.parse_known_args()

    # Import logic
    mod_str, _, func_str = args.entry_func.rpartition(".")
    try:
        module = import_module(mod_str)
        func = getattr(module, func_str)
    except (ImportError, ValueError) as e:
        arg_parser.error(e)
    except AttributeError as e:
        arg_parser.error(e)

    app = func(extra_args)
    web.run_app(app, host=args.hostname, port=args.port)
    arg_parser.exit(message="Stopped\n")
