# Dump git clone network requests

- Install mitmproxy: https://www.mitmproxy.org/
- Dump the network packets: `mitmdump -w dump.txt`
- configure git to use the proxy and clone
   - `git config --global http.proxy localhost:8080`
   - `git -c http.sslVerify=false clone https://github.com/codecrafters-io/git-sample-1`
   - `git config --global --unset http.proxy`
- Inspect: `mitmweb -r dump.txt`

