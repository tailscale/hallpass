# Hallpass

**Warning:** work-in-progress. Do not use.

This is a Just-in-Time (JIT) access request web app. It's like
https://github.com/tailscale/accessbot but without the Slack bit and
instead being a webserver.

It's a [`tsnet`](https://tailscale.com/kb/1244/tsnet) webserver, so it
knows who you are already and which device you want access for.

It gets its secrets from [setec](https://github.com/tailscale/setec/).
