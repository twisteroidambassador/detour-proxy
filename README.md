# detour-proxy
A spiritual clone of Lantern's ["`detour`"](https://github.com/getlantern/detour) component, written in Python + asyncio. This is a proxy server that tries to connect directly, and when that fails, falls back on a chained proxy server。

Requires Python 3.5 or newer, and `aiosocks`.

## Usage
* Obtain access to an upstream SOCKS4 / SOCKS5 proxy server.
* Edit the configuration variables near the top of the script.
* Optionally, prepare a file `whitelist.txt` containing hostnames that should always be connected through the upstream proxy, and put it in the same directory as the script.
* Run the script, and set the configured listening address as your application's SOCKS5 proxy server.

When the script receives a connection request, it first attempts to connect to the destination directly. If the connection times out, or otherwise results in an error, subsequent connection attempts will be made through the upstream proxy. (The actual logic is *slightly* more complex than that.) The end result is that destinations that cannot be reached directly will be automatically detoured to the upstream proxy.

### Differences from Lantern's detour
At first I tried to extract `detour` from Lantern and make it a standalone tool, however I did not know golang, and apparently one day's worth of crash courses does not enable one to accomplish the task. Therefore, I implemented something similar in Python.

Key differences between `detour` and this script:

* `detour` seems to be a first-class HTTP proxy, while this script is a SOCKS5 proxy.
* `detour` detects HTTP redirections and connection hijacks to censor pages, this script doesn't.
* `detour` buffers the initial request sent on a direct connection, and if the connection fails midway (getting RST'ed, being redirected to a censor page, etc.), may resend the request on the detoured connection. This script does not have similar functionality.

Despite these shortcomings, this script works well enough to be useful, so here you go.
