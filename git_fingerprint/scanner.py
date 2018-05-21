#!/usr/bin/env python3
import hashlib
from functools import lru_cache, partial
from multiprocessing.pool import ThreadPool
from io import BytesIO
from os import walk
from os.path import join, relpath, isfile
from collections import defaultdict
from traceback import format_tb
from typing import Tuple, Set, List
from shutil import copytree

import requests
from axel import Event
from git import Repo, GitCommandError

from .helpers import OrderedDefaultDict, temporary_directory, chunks
from .exceptions import GitFingerprintException


class Scanner:
    """
    Core scanner class
    Handles iteration and keeps track of all files
    """
    MODE_TAG = "tag"
    MODE_COMMIT = "commit"
    MODE_BRANCH = "branch"

    LOG_LEVEL_INFO = "*"
    LOG_LEVEL_ERROR = "!"
    LOG_LEVEL_WARNING = "-"
    LOG_LEVEL_SUCCESS = "+"

    def __init__(self, url: str="", mode: str=MODE_BRANCH, webroot: str="",
                 git_repo_path: str= "", max_remote_threads: int=10,
                 max_local_threads: int=5, verify_ssl: bool=True, debug: bool=False,
                 session: requests.Session=None):
        """
        Scanner constructor
        :param url: Base url of the remote host
        :param mode: Scan mode (tag, commit, branch)
        :param webroot: Local webroot in the git path
        :param git_repo_path: Local git repository path
        :param max_remote_threads: Maximum amount of threads to use while connecting to the remote host
        :param verify_ssl: Should SSL certificates be verified?
        :param session: Optional requests object, used to fetch data
        """
        self.__url = url.rstrip("/") + "/"
        self._mode = mode
        self.__root = webroot.lstrip("\\/")
        self._files_local = OrderedDefaultDict(dict)
        self.__files_remote = OrderedDefaultDict(dict)
        self.__max_remote_threads = max_remote_threads
        self._max_local_threads = max_local_threads
        self.__session = session or requests
        self.__verify_ssl = verify_ssl
        self.__repo = Repo(path=git_repo_path)
        self.__repo.heads.master.checkout("-f")
        self.__base = join(self.git_path, self.__root)
        self.__request_count = 0
        self._hashing_algorithm = "sha256"
        self.__hashing_interrupted = False
        self.__debug = debug

        self.on_log = Event()
        self.on_progress = Event()

    @property
    def hashing_algorithm(self):
        """
        Get he currently used hashing algorithm
        :return: String
        """
        return self._hashing_algorithm

    @hashing_algorithm.setter
    def hashing_algorithm(self, algorithm: str):
        """
        Set the hashing algorithm to use
        :param algorithm: String
        :return: None
        """
        if algorithm not in hashlib.algorithms_guaranteed:
            raise GitFingerprintException(
                f"Invalid hashing algorithm '{algorithm}', accepted algorithms: "
                f"{', '.join(hashlib.algorithms_guaranteed)}.")

        self._hashing_algorithm = algorithm

    @property
    def cache(self):
        """
        Get the local cache
        :return: Ordered dict, 
        """
        return {
            "hashing_algorithm": self._hashing_algorithm,
            "files": list(self._files_local.items())
        }

    @cache.setter
    def cache(self, cache):
        """
        Restore local files from a previous session (validate if the cache is valid)
        :return: None
        """
        if cache.get("hashing_algorithm") != self._hashing_algorithm:
            raise GitFingerprintException(
                f"Refused to overwrite cache, hashing algorithm "
                f"'{cache.get('hashing_algorithm')}' does not match hashing "
                f"algorithm '{self._hashing_algorithm}'.")

        for head, files in cache.get("files", []):
            self._files_local[head] = files

    @property
    @lru_cache()
    def results(self):
        """
        Calculate all results and sort them
        :return: Sorted results by amount of valid hashes and total successful hits
        """
        results = defaultdict(dict)
        remote = {}

        for file, details in self.__files_remote.items():
            if details.get("status") != 404:
                remote[file] = details
        
        total_hits = len(remote)

        for head, files in self.__get_hashes_per_head():
            results[head]["hits"] = total_hits / (len(files) / 100)
            results[head]["hits"] = results[head]["hits"] if results[head]["hits"] < 100 else 100
            results[head]["hashes"] = 0

            for file, details in remote.items():
                if file in files and details.get("hash") == files[file]:
                    results[head]["hashes"] += 1

            results[head]["hashes"] = results[head]["hashes"] / (total_hits / 100)

        return sorted(results.items(), key=lambda x: (
            x[1]["hashes"],
            x[1]["hits"]
        ), reverse=True)

    @property
    @lru_cache()
    def all_heads(self):
        """
        Get a list of all local heads
        :return: List of unique heads
        """
        return set(self._files_local.keys())

    @property
    @lru_cache()
    def all_files(self) -> Set[str]:
        """
        Unique list of all files
        :return: List of all unique file names
        """
        return set(self.__all_files())

    def __all_files(self):
        """
        Get all files used in the tree structure
        :return: Iterator of strings
        """
        for head, files in self._files_local.items():
            for file in files.keys():
                yield file

    def __get_hashes_per_head(self):
        """
        Get all hashes per head, prevents us from having to copy deep structures
        into memory, this method creates the dictionary as the head moves from
        commit to commit.

        :return: Iterator 
        """
        tracker = {}

        for head, files in self._files_local.items():
            for file, file_hash in files.items():
                if file_hash is not None:
                    tracker[file] = file_hash
                if file_hash is None and file in tracker:
                    del tracker[file]

            yield head, tracker

    @property
    @lru_cache()
    def mode(self) -> str:
        """
        Mode getter, converts all half
        :return: String
        """
        for key in dir(self):
            if key.startswith("MODE_"):
                if getattr(self, key)[0].lower() == self._mode[0].lower():
                    return getattr(self, key)

        raise GitFingerprintException(f"Invalid scan mode: {self._mode}.")

    @property
    def git_path(self) -> str:
        """
        Getter for the absolute git path
        :return: String
        """
        return self.__repo.working_dir

    def log(self, message, level: str=LOG_LEVEL_INFO):
        """
        Shorthand for firing the log event
        :param message: 
        :param level: 
        :return: 
        """
        self.on_log.fire(message, level)

    def scan_local(self):
        """
        Build the local file tree
        :return: None
        """
        self.log(
            f"Building {self.mode} tree with hashing "
            f"algorithm {self.hashing_algorithm}..")

        if self.mode == self.MODE_BRANCH:
            self.__build_file_tree(self.__branch_iterator())
        if self.mode == self.MODE_TAG:
            self.__build_file_tree(self.__tag_iterator())
        if self.mode == self.MODE_COMMIT:
            self.__build_commit_tree()

    def scan_remote(self):
        """
        Start scanning the remote host and return the results
        :return: None
        """
        self.log(
            f"Scanning remote host ({len(self.all_files)} files "
            f"over {len(self._files_local)} {self.mode}s)..")

        pool = ThreadPool(self.__max_remote_threads)
        pool.map_async(self.request, self.all_files)
        pool.close()
        pool.join()

    def __build_commit_tree(self):
        def on_error(e):
            print(str(e) + "\n" + "".join(format_tb(e.__traceback__)))
            exit(1)

        cache = next(reversed(self._files_local), None)
        total = self.__repo.head.commit.count()

        commits = []

        for commit in self.__repo.iter_commits(reverse=True):
            if commit.hexsha not in self._files_local:
                commits.append(commit.hexsha)

        commits = chunks(commits, self._max_local_threads)
        commit_chunk_size = len(next(iter(commits), []))

        builder = partial(self.__build_commit_tree_thread, total)

        if cache:
            self.log(f"Starting at cached commit: {cache}", self.LOG_LEVEL_INFO)

        pool = ThreadPool(processes=self._max_local_threads + 1)

        try:
            self.log(
                f"Setting up {self._max_local_threads} temporary repositories "
                f"and assigning {commit_chunk_size} commits per thread (total "
                f"commits: {total}).")

            pool.map_async(builder, commits, error_callback=on_error)
            pool.close()
            pool.join()

        except KeyboardInterrupt:
            self.log("Interrupt detected, halting threads..", self.LOG_LEVEL_WARNING)
            self.__hashing_interrupted = True
            pool.join()
            raise

        finally:
            self.log("Cleaning up temporary repositories..")

        self.log("Finished building commit tree..")

    @temporary_directory
    def __build_commit_tree_thread(self, temp: str, total: int, commits: List[str]):
        """
        Build a part of the commit tree in a thread 
        :param temp: 
        :param total: 
        :param commits: 
        :return: 
        """
        if self.__debug:
            self.log(f"Setting up temporary repository in: {temp}")

        copytree(join(self.git_path, ".git"), join(temp, ".git"))
        temp_repo = Repo(temp)
        temp_repo.git.checkout("master", "-f")

        for index, commit in enumerate(commits):
            if self.__hashing_interrupted:
                break

            if index % 5 == 0:
                self.on_progress.fire(current=len(self._files_local) + 1, total=total)

            try:
                temp_repo.git.checkout(commit, "-f")
                files = temp_repo.head.commit.stats.files
                self._files_local[commit] = {}  # Ensures it gets skipped next time round

            except (GitCommandError, OSError, ValueError):
                break

            for file in files:
                if not file.startswith(self.__root):
                    continue

                path = join(temp, file)
                file = relpath(file, self.__root)

                if isfile(path):
                    with open(path, "rb") as buff:
                        self._files_local[commit][file] = self.hash(buff)
                else:
                    self._files_local[commit][file] = None

    def __branch_iterator(self):
        """
        Walk over all branches in the head and check them out
        :return: Head
        """
        for branch in self.__repo.git.branch("-a").splitlines(keepends=False):
            if " -> " in branch:
                continue

            branch = branch.strip("* ")
            self.__repo.git.checkout(branch)
            yield from self.__walk_local_files(branch)

    def __tag_iterator(self):
        """
        Walk over all tags individually
        :return: Head
        """
        for tag in self.__repo.tags:
            self.log(f"Scanning tag '{tag.name}'..")
            self.__repo.git.checkout(tag.name)
            yield from self.__walk_local_files(tag.name)

    def __walk_local_files(self, head) -> Tuple[str, str]:
        """
        Method that walks over all files, and joins their relative paths
        :return: Tuple
        """
        for path, _, files in walk(self.__base):
            for file in files:
                with open(join(path, file), "rb") as buff:
                    yield head, relpath(join(path, file), self.__base), self.hash(buff)

    def __build_file_tree(self, iterator):
        """
        Generic 'build file tree' method
        :param iterator: 
        :return: 
        """
        for head, file, file_hash in iterator:
            self._files_local[head][file] = file_hash

    def request(self, file):
        """
        Make a (threaded) request to the server
        :param file: File we're going to request
        """
        resp = self.__session.get(self.__url + file, allow_redirects=False, verify=self.__verify_ssl)
        self.__files_remote[file]["hash"] = self.hash(BytesIO(resp.content))
        self.__files_remote[file]["status"] = resp.status_code
        self.__request_count += 1

        if self.__request_count % 10 == 0:
            self.on_progress.fire(count=self.__request_count)

    def hash(self, file, block_size=65536) -> str:
        """
        Hash a file efficiently using the algorithm specified
        :param file: File like object to hash 
        :param block_size: Buffer size
        :return: Hash as a string
        """
        algo = getattr(hashlib, self._hashing_algorithm)()

        for block in iter(lambda: file.read(block_size), b""):
            algo.update(block)

        return str(algo.hexdigest())
