# Dump git clone network requests

- Install mitmproxy: https://www.mitmproxy.org/
- Dump the network packets: `mitmdump -w dump.txt`
- configure git to use the proxy and clone
   - `git config --global http.proxy localhost:8080`
   - `git -c http.sslVerify=false clone https://github.com/codecrafters-io/git-sample-1`
   - `git config --global --unset http.proxy`
- Inspect: `mitmweb -r dump.txt`

# Libcurl

## receiving data:

- https://www.youtube.com/watch?v=nbTaHEocCuo

# Initial Client Request:

## Request 

> GET https://github.com/codecrafters-io/git-sample-1/info/refs?service=git-upload-pack



## Response:

```
001e# service=git-upload-pack
0000000eversion 2
0028agent=git/github-26eb2912769f-Linux
0013ls-refs=unborn
0027fetch=shallow wait-for-done filter
0012server-option
0017object-format=sha1
0000
```



## Capability Advertisement:

See the capabilities doc here: https://git-scm.com/docs/protocol-v2#_capabilities

- agent: git/github-26eb2912769f-Linux
  - Server is running on this version of git
- ls-refs: [unborn](https://git-scm.com/docs/gitglossary#Documentation/gitglossary.txt-unborn)
- fetch: shallow wait-for-done filter
- server-option
  - here it allows the following object-format capability to be used
- object-format: sha1
  - server is able to deal with hash algorithm sha1



# ls-refs request

See: https://git-scm.com/docs/protocol-v2#_command_request

## Request

> POST https://github.com/codecrafters-io/git-sample-1/git-upload-pack 

payload

```
0014command=ls-refs
001aagent=git/2.52.0-Linux0016object-format=sha100010009peel
000csymrefs
000bunborn
001bref-prefix refs/heads/
001aref-prefix refs/tags/
0014ref-prefix HEAD
0000
```

- command: ls-refs

- capability-list:
  - agent: git/2.52.0-Linux
    -  The client may optionally send its own agent string by including the agent capability with a value Y (in the form agent=Y) in its request to the server (but it MUST NOT do so if the server did not advertise the agent capability).
  - object-format: preferred object format by client
- 0001 (delimiter)
- command-args: see https://git-scm.com/docs/protocol-v2#_ls_refs
  - peel
  - symrefs
  - unborn
  - ref-prefix: only show the refs with these prefixes



## Response

```
005247b37f1a82bfe85f6d8df52b6258b75e4343b7fd HEAD symref-target:refs/heads/master
003f47b37f1a82bfe85f6d8df52b6258b75e4343b7fd refs/heads/master
0000
```



# fetch request

See: https://git-scm.com/docs/protocol-v2#_fetch

## Request:

POST https://github.com/codecrafters-io/git-sample-1/git-upload-pack

payload:

```
0011command=fetch001aagent=git/2.52.0-Linux0016object-format=sha10001000dthin-pack000dofs-delta0032want 47b37f1a82bfe85f6d8df52b6258b75e4343b7fd
0032want 47b37f1a82bfe85f6d8df52b6258b75e4343b7fd
0009done
0000
```

- command: fetch
- capability-list: same as ls-ref
- 0001 (delimiter)
- command-args:
  - thin-pack: pack with deltas to reduce network traffic, client side needs to do the parsing and recovering based on the thin pack.
  - ofs-delta: client can read OBJ_OFS_DELTA (aka type 6) in a packfile.
  - want: object id that client wants
    - here it is 005247b37f1a82bfe85f6d8df52b6258b75e4343b7fd, the advertised objects by server in the ls-refs
  - done: negotiation is done, get me the packfiles. 



## Response 

This part is basically the pack file. 

TODO: use imhex to open the response and analyze the result, things to look for:

- sideband-64k
- https://git-scm.com/book/en/v2/Git-Internals-Transfer-Protocol

- The data transfer of the packfile is always multiplexed, using the same semantics of the *side-band-64k* capability from protocol version 1. This means that each packet, during the packfile data stream, is made up of a leading 4-byte pkt-line length (typical of the pkt-line format), followed by a 1-byte stream code, followed by the actual data.

  ```
   The stream code can be one of:
  1 - pack data
  2 - progress messages
  3 - fatal error message just before stream aborts
  ```

