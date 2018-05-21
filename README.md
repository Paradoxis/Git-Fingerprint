# Git-Fingerprint
Git Fingerprint is a web fingerprinting tool that attempts to scan a target based on the files a git repository by enumerating over all files ever found in the public web root and comparing cryptographic hashes of each commit, branch or tag in order to calculate the best possible match.

## Requirements
* Python 3.6+
* A good CPU

## Installation
For local installation:
```
$ pip install git-fingerprint
```

For development installation:

```
$ pip install .
```



## Usage

```
$ git-fingerprint --help
usage: Git Fingerprint - A git-based web fingerprinting tool
       [-h] [-u URL] [-w WEBROOT] [-m MODE] [-r REPO] [-a ALGORITHM]
       [-t THREADS] [-T LOCAL_THREADS] [-f FORMAT] [-l LIMIT] [-c CACHE] [-s]
       [-i] [-d]

Git Fingerprint is a web fingerprinting tool that attempts to scan a target
based on the files a git repository by enumerating over all files ever found
in the public web root and comparing cryptographic hashes of each commit,
branch or tag in order to calculate the best possible match.

optional arguments:
  -h, --help
       show this help message and exit

  -u URL, --url URL
       Specifies the base url of a remote host to scan. If not set, the script
       will only generate a local file hashing cache.

  -w WEBROOT, --webroot WEBROOT
       Pointer to the public web root that should be scanned (eg:
       /usr/local/www/). Defaults to the root of the git repository.

  -m MODE, --mode MODE
       Fingerprinting mode, specifies how verbose the scanning should be. Note
       that scanning with 'commit' mode will have to hash each file of each
       commit and might take a long time, using the cache is recommended when
       this mode is selected. Value must be one of: b[ranch], t[ag], c[ommit].
       Default: 'branch'.

  -r REPO, --repo REPO
       Path to the git directory to scan, defaults to the current directory.

  -a ALGORITHM, --algorithm ALGORITHM
       Hashing algorithm that should be used to calculate the local file
       hashes. While using hashing algorithm such as 'md5' would make the scan
       faster, the accuracy of the scan will be decreased. Defaults to:
       'sha256'. Accepted algorithms: sha3_256, shake_128, shake_256, blake2s,
       md5, sha224, sha3_224, sha3_512, sha384, blake2b, sha512, sha1,
       sha3_384, sha256.

  -t THREADS, --threads THREADS
       Number of threads used to fingerprint the remote server. Using a high
       number of threads is discourage as to avoid detection or rate limit
       issues. Default: 10

  -T LOCAL_THREADS, --local-threads LOCAL_THREADS
       Number of local threads to use to hash the local files per commit.
       Default: 5

  -f FORMAT, --format FORMAT
       Output format of the scan result. If not set, the default ASCII table
       will be printed instead. If enabled, all other logging will be
       redirected to stderr. Accepts: p[lain], j[son], x[ml]

  -l LIMIT, --limit LIMIT
       Number of matching entries to show. If set to 'none', all possible
       entries will be shown. Default: 10

  -c CACHE, --cache CACHE
       Specifies the file which should be used for loading/saving the local
       cache. Default: .git-fingerprint.json

  -s, --stfu, --silent
       Enable silent mode and only display the output of the script.

  -i, --insecure
       Disables SSL certificate checking, default: certificate checking
       enabled.

  -d, --debug
       Enable debug logging, default: disabled
```
