# oauth-token-proxy

[![Build Status](https://travis-ci.org/paulrosania/oauth-token-proxy.svg?branch=master)](https://travis-ci.org/paulrosania/oauth-token-proxy)

A thin proxy for OAuth-secured (JSON) REST APIs.

## Motivation

oauth-token-proxy enables mobile apps and single-page web apps (SPAs) to use the
OAuth authorization code flow without exposing their client credentials.

## Limitations

oauth-proxy refuses to wrap non-JSON APIs. It enforces this by rejecting all
requests with Content-Type headers other than `application/json`. It does this
to protect against CSRF attacks. (In general, browsers cannot send cross-origin
JSON requests.)

A "synchronizer token"-based approach would enable oauth-proxy to wrap non-JSON
APIs, at the cost of minor implementation overhead. (This approach would also
protect against browser security bugs.) If you're interested in implementing
this, let me know! I'm happy to accept a patch.

## Installation

    go get -u github.com/paulrosania/oauth-token-proxy

## Documentation

Full API documentation is available here:

[https://godoc.org/github.com/paulrosania/oauth-token-proxy](https://godoc.org/github.com/paulrosania/oauth-token-proxy)

## Contributing

1. Fork the project
2. Make your changes
2. Run tests (`go test`)
3. Send a pull request!

If you're making a big change, please open an issue first, so we can discuss.

## License

MIT
