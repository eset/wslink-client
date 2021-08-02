WslinkClient
============

WslinkClient is a client intended to communicate with
[Wslink](https://www.welivesecurity.com/2021/10/27/wslink-unique-undocumented-malicious-loader-runs-server/), which is a unique loader running as a server and
executing received modules in-memory. It was initially made to experiment with
detection methods.

The client might be of interest to beginners in malware analysis - it shows how
one can reuse existing functions of analyzed malware and interact with it.

WslinkClient simply establishes connection with Wslink and sends a module which
is subsequently executed.

The code reuses a few functions from a non-virtualized unpacked sample, which
is available on VirusTotal. SHA-1 of the sample is
``840BBD3475B189DBB65F2CD4E6C060FE3E071D97``. Note that you must still patch
its public key and load it yourself to test it since we do not want to publish
a ready-to-use loader.

Compilation
===========

The code was compiled with the supplied Makefile running on Ubuntu 20.04
with Linux 5.4.0. The binaries are included in the
[GitHub releases section](https://github.com/eset/wslink-client/releases).
