#!/usr/bin/env python3
import os
import sys
import json
import hashlib

from typing import Optional
from urllib3 import disable_warnings
from argparse import ArgumentParser
from multiprocessing import BoundedSemaphore
from xml.dom.minidom import parseString

from dicttoxml import dicttoxml
from tabulate import tabulate
from progressbar import ProgressBar

from git_fingerprint import Scanner
from git_fingerprint import __author__, __version__
from git_fingerprint.helpers import CustomHelpFormatter

FORMAT_XML = "x"
FORMAT_JSON = "j"
FORMAT_PLAIN = "p"

args = None
lock = BoundedSemaphore()
progress_bar = ProgressBar()


def write(text, bubble: Optional[str]="*", divider=False):
    """
    Write a thread-safe message
    :param text: Text to write
    :param bubble: Bubble to write
    :param divider: Should a divider be written?
    :return: None
    """
    if args.stfu:
        return

    lock.acquire()

    if bubble:
        print("[{}] {}{}".format(bubble, text, "\n" if divider else ""))
    else:
        print("{}{}".format(text, "\n" if divider else ""))

    lock.release()


def progress(current, total):
    """
    Callback that's fired when the progressbar is called
    :param current: Current index
    :param total: Goal index
    :return: None
    """
    lock.acquire()
    progress_bar.min_value = 0
    progress_bar.max_value = total
    progress_bar.update(value=current)
    lock.release()


def main():
    """
    Main entry point of the script
    :return: None
    """
    global args

    parser = ArgumentParser(
        formatter_class=CustomHelpFormatter,
        prog="Git Fingerprint - A git-based web fingerprinting tool",
        description=
            "Git Fingerprint is a web fingerprinting tool that attempts to scan "
            "a target based on the files a git repository by enumerating over "
            "all files ever found in the public web root and comparing "
            "cryptographic hashes of each commit, branch or tag in order to "
            "calculate the best possible match.")

    parser.add_argument("-u", "--url", default="", help=
        "Specifies the base url of a remote host to scan. If not set, "
        "the script will only generate a local file hashing cache.")

    parser.add_argument("-w", "--webroot", default="", help=
        "Pointer to the public web root that should be scanned (eg: "
        "/usr/local/www/). Defaults to the root of the git repository.")

    parser.add_argument("-m", "--mode", help=
        "Fingerprinting mode, specifies how verbose the scanning should "
        "be. Note that scanning with 'commit' mode will have to hash each "
        "file of each commit and might take a long time, using the cache is "
        "recommended when this mode is selected. Value must be one of: b[ranch], "
        "t[ag], c[ommit]. Default: 'branch'.", default="branch")

    parser.add_argument("-r", "--repo", default="", help=
        "Path to the git directory to scan, defaults to the current directory. ")

    parser.add_argument("-a", "--algorithm", default="sha256", help=
        f"Hashing algorithm that should be used to calculate the local file hashes. "
        f"While using hashing algorithm such as 'md5' would make the scan faster, "
        f"the accuracy of the scan will be decreased. Defaults to: 'sha256'. "
        f"Accepted algorithms: {', '.join(hashlib.algorithms_guaranteed)}.")

    parser.add_argument("-t", "--threads", default=10, type=int, help=
        "Number of threads used to fingerprint the remote server. Using a high "
        "number of threads is discourage as to avoid detection or rate limit "
        "issues. Default: 10")

    parser.add_argument("-T", "--local-threads", default=5, type=int, help=
        "Number of local threads to use to hash the local files per commit. "
        "Default: 5")

    parser.add_argument("-f", "--format", help=
        "Output format of the scan result. If not set, the default ASCII table "
        "will be printed instead. If enabled, all other logging will be "
        "redirected to stderr. Accepts: p[lain], j[son], x[ml]")

    parser.add_argument("-l", "--limit", default="10", help=
        "Number of matching entries to show.  If set to 'none', all possible "
        "entries will be shown. Default: 10")

    parser.add_argument("-c", "--cache", default=".git-fingerprint.json", help=
        "Specifies the file which should be used for loading/saving the local cache. "
        "Default: .git-fingerprint.json")

    parser.add_argument("-s", "--stfu", "--silent", action="store_true", help=
        "Enable silent mode and only display the output of the script.")

    parser.add_argument("-i", "--insecure", action="store_true", default=False, help=
        "Disables SSL certificate checking, default: certificate checking enabled.")

    parser.add_argument("-d", "--debug", action="store_true", default=False, help=
        "Enable debug logging, default: disabled")

    args = parser.parse_args()

    # Print header
    write("Starting Git Fingerprint | {}".format(__version__), "+")
    write("Copyright (c) 2018 - {}".format(__author__), "+", divider=True)

    # Disable requests HTTPS certificate errors
    disable_warnings()

    # Set up scanner
    scan = Scanner(
        url=args.url,
        mode=args.mode,
        verify_ssl=not args.insecure,
        webroot=args.webroot,
        git_repo_path=args.repo,
        max_remote_threads=args.threads,
        max_local_threads=args.local_threads,
        debug=args.debug)

    scan.hashing_algorithm = args.algorithm

    # Add progress callbacks
    if not args.stfu:
        scan.on_log += write
        scan.on_progress += progress


    # Load cache
    if os.path.isfile(args.cache):
        with open(args.cache) as cache:
            write("Loading cache from '{}'..".format(args.cache), "*")
            scan.cache = json.load(cache)

    # Scan local git repository
    try:
        scan.scan_local()

    # Handle keyboard interrupts
    except KeyboardInterrupt:
        write("Aborted")
        exit(1)

    # Dump cache before exiting
    finally:
        with open(args.cache, "w") as cache:
            write("Dumping cache..", "*")
            json.dump(scan.cache, cache, indent=2)


    # Scan remote host
    if not args.url:
        return

    scan.scan_remote()


    # Output results
    if args.limit == "none":
        results = scan.results
    else:
        limit = int(args.limit)
        results = scan.results[:limit]

    if args.format[0] == FORMAT_PLAIN:
        print("head, hashes, hits")
        for key, result in results:
            print(",".join((key, result["hashes"], result["hits"])))

    elif args.format[0] == FORMAT_JSON:
        json.dump(results, sys.stdout, indent=2)

    elif args.format[0] == FORMAT_XML:
        print(parseString(
            dicttoxml(
                results,
                attr_type=False,
                custom_root="git-fingerprint",
                item_func=lambda i: "fingerprint")
        ).toprettyxml())

    else:
        print(tabulate((
            (
                key,
                "{0:05.1f}%".format(result["hashes"]),
                "{0:05.1f}%".format(result["hits"])
            ) for key, result in results
        ), [
            scan.mode.capitalize(), "Matching hashes", "Successful hits"
        ], tablefmt="grid", numalign="right"))


if __name__ == "__main__":
    main()
