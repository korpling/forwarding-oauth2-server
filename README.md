# OAuth2 server for wrapping Shibboleth IdPs

This is a server that creates an OAuth2 Server (identity provider).
It assumes it runs behind as protected resource (e.g. by securing it with `AuthType shibboleth` in an Apache 2 server). 
Shibboleth/SAML meta data fields that are passed through as HTTP headers (like `X-Remote-User`) variables can be mapped to JWT token attributes.

**This is currently a prototype and production ready!!!**

The server is implemented in Rust, using the [oxid-auth](https://github.com/HeroicKatora/oxide-auth/) library.
