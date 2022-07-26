# OAuth2 server for wrapping Shibboleth IdPs

This is a server that creates an [OAuth2](https://oauth.net/2/) Server (identity provider).
It assumes it runs behind as protected resource (e.g. by securing it with `AuthType shibboleth` in an Apache 2 server). 
Shibboleth/SAML meta data fields that are passed through as HTTP headers (like `X-Remote-User`) variables can be mapped to [JWT token](https://jwt.io/) attributes.



## Background

This project will be used as identity provider for the [ANNIS frontend](https://github.com/korpling/ANNIS) when an institutional Shibboleth identity provider (like the DFN AAI) should be used.

## Installation and configuration

### Configure Apache2 with Shibboleth

Follow one of the Shibboleth guides like in the [Shibboleth Wiki](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065335062/Apache) to configure your Apache with a location secured by Shibboleth.
This secured location must be forwared to the actual web service we are going to install.

```
<Location /login>
        # Proxy all requests to /login to our service at port 8020
        ProxyPass http://localhost:8020
        ProxyPassReverse http://localhost:8020
</Location>
<Location /login/authorize>
      AuthType shibboleth
      ShibRequestSetting requireSession true
      <RequireAll>
              Require shib-session
              # Add more conditions on the user here
      </RequireAll>
      # This is important since we want to use the forwarded headers
      ShibUseHeaders On

</Location>
```

### Installation of the service binary

1. To install this binary as a service you will need a working Rust compiler environment, which can be installed with <https://rustup.rs/>
2. Compile the binary with `cargo install forwarding-oauth2-server`,
3. Copy the resulting binary file to you system-wide binary folder
```bash
cp ~/.cargo/bin/forwarding-oauth2-server /usr/local/bin/
```
4. For [systemd](https://wiki.debian.org/systemd/Services) based Linux servers like Ubuntu 18.04, create a service unit definition file with a `.service` suffix in the `/etc/systemd/system` directory. This file could look like following example. Also make sure to choose a user (here `youruser`) this service should run as.

```
[Unit]
Description=Authorization token wrapper for ANNIS

[Service]
Type=simple
ExecStart=/usr/local/bin/forwarding-oauth2-server -c /usr/local/etc/forwarding-oauth2-server.toml
User=youruser
Group=youruser
WorkingDirectory=/usr/local/

[Install]
WantedBy=multi-user.target
```

Execute
```bash
systemctl daemon-reload
```
to make the new file known to the system.

For non-systemd-based servers use the operating system manual to define a corresponding service.

### Configuration file

In the previous service definition, the `/usr/local/etc/forwarding-oauth2-server.toml` file was used as configuration file.
You can copy one of the example files in the `examples/` folder and adjust them to your needs.
We use TOML files, which syntax is documented at <https://toml.io/>

```toml
[bind]
# Define the port to use for the service
port = 8020

[mapping]
# List all headers that should be forwared from Apache2 to the 
include_headers = ["x-admin"]
# Path to the template file that is used to generate the JWT tokens
token_template = "<path-to-template-file>"
# The default value for the "sub" field
default_sub = "academic"

[client]
# Define the OAuth2 client ID
id = "Shibboleth"
# A valid redirect URI
redirect_uri = "https://youapplicationserver/appcontext/"

[client.token_verification]
# Define a secret to be shared between identity provider and service consuming the JWT token
type = "HS256"
secret = "random-words-are-not-secure-please-change-me"
# Alternativly, you can use a private/public key approach
# type = "RS256"
# private_key = "yourprivatekey"
# public_key = "yourpublikey"
```

### Token template

JWT tokens are created using a template file, which is given as `token_template` field in the `mapping` section of the configuration file. 
We use the template language [Handlebars](https://handlebarsjs.com/) for including dynamic content like the user name (given as `sub` variable).
Also, all forwarded headers which are defined in the `include_header` field of the configuration variable can be used inside the JWT token definition.

```
{
    "sub": "{{sub}}",
    "exp": {{exp}},
    {{#if x-admin}}
    "https://corpus-tools.org/annis/roles": ["admin"],
    {{/if}}
    "https://corpus-tools.org/annis/groups": ["academic"]
}
```

### Start and test the service

When you installed the service, created the configuration files and secured the `/login` path, you should be able to start the newly defined service.
If the service unit file was named `shib-wrapper.service` you can start and enable the service at each boot with 

```bash
systemctl enable shib-wrapper.service
systemctl start shib-wrapper.service
```

### Configure the application to use this OAuth2 identity provider

If your application uses Spring Security (like e.g. ANNIS), you can configure the endpoints of this OAuth2 service like this in your application properties:

```properties
spring.security.oauth2.client.registration.shib.client-id=Shibboleth
spring.security.oauth2.client.registration.shib.authorization-grant-type=authorization_code
spring.security.oauth2.client.registration.shib.redirect-uri=https://youapplicationserver/appcontext/login/oauth2/code/shib

spring.security.oauth2.client.provider.shib.authorization-uri=https://yourserver/login/authorize
spring.security.oauth2.client.provider.shib.token-uri=https://yourserver/login/authorize/token
spring.security.oauth2.client.provider.shib.user-info-urihttps://yourserver/login/userinfo
spring.security.oauth2.client.provider.shib.user-name-attribute=sub

```

## 3rd party dependencies

This software depends on several 3rd party libraries. These are documented in the "third-party-licenses.html" file in this folder.
