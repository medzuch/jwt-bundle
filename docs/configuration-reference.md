# Configuration reference

Every `medzuch_jwt` option, with its default, what it means and an example — the
whole tree, including the corners no example in the README reaches.

This file is **generated**, not written. It is the output of

```bash
bin/console config:dump-reference medzuch_jwt
```

which prints the same thing against the version an application actually has
installed. That command is the one to trust; this copy exists so that the
configuration surface is *recorded*, and so a rename or a removal has something
to fail against. `ConfigurationReferenceTest` compares this file against that
command and nothing else — it does not rewrite it, because a test able to
rewrite its own expectation is a test an environment variable can silence.
Recording a change is `make config-reference`, a command someone runs and a diff
someone reads; the failure message names it.

Fenced as `text` rather than `yaml` on purpose. It is a reference, not a
configuration that compiles — required options appear here with their
placeholders, so pasting the whole thing into an application would not boot
(see CONTRIBUTING, ground rule 7).

Byte for byte the same from Symfony 6.4.44 through 8.1.5, which is what makes an
exact comparison the right assertion rather than a normalised one. Symfony 6.4.0
renders an array node's examples differently — no `[]` for an empty default, the
example items uncommented — so on a tree resolved with `--prefer-lowest` the
comparison is skipped: what differs there is upstream's formatting, not this
tree.

```text
# Default configuration for extension with alias: "medzuch_jwt"
medzuch_jwt:

    # Service id of a PSR-20 clock. Null uses the library's SystemClock.
    clock:                null # Example: app.frozen_clock

    # The PSR-3 level each kind of diagnostic is emitted at. The library decides the level; your logger decides whether to record it — so this is how a resource server stops paying for a line per accepted token, or starts alerting on refusals. Unset, each keeps the library's default. Read only where a `logger` is configured.
    log_levels:

        # A token that passed every check. `debug` by default, because on a busy API this is one line per request.
        accepted:             null # Example: info

        # Signature, algorithm allowlist, or key resolution while verifying — an integrity problem rather than a policy one. `warning` by default.
        verification_failed:  null # Example: error

        # A properly signed token whose claims are refused: expired, not yet valid, wrong issuer or audience, a missing required claim, a profile rule. `notice` by default, because this is the ordinary cost of short lifetimes.
        claim_rejected:       null # Example: info

        # A remote JWK Set fetched, served from cache, or refreshed. `debug` by default.
        key_resolution:       null # Example: info

        # A remote JWK Set that could not be fetched or parsed — an outage on one side or the other. `warning` by default.
        key_resolution_failed: null # Example: critical

        # An encrypted token whose outer JWE decrypted and authenticated, before anything inside it was read. `debug` by default; read only where a consumer configures `jwe`.
        decrypted:            null # Example: info

        # An encrypted token that would not decrypt: the wrong key, or ciphertext that has been altered since it was written. `warning` by default, and the one category here that is never the ordinary cost of anything.
        decryption_failed:    null # Example: critical

    # Service id of a PSR-3 logger. Null disables logging entirely.
    logger:               null # Example: monolog.logger.jwt

    # Named keys, referenced by name from consumers, issuers, ID token registrations, security event streams and the published JWK Set.
    keys:

        # Prototype
        name:

            # Shared secret, at least 32/48/64 bytes for HS256/384/512 (RFC 8725 §3.5). Use an env reference; %env(base64:NAME)% decodes a base64 secret. The length cannot be checked at build: the secret stays an env reference so it never reaches a container parameter, so a short one fails when the key is first used.
            hmac:                 ~ # Example: '%env(JWT_SECRET)%'

            # Signing key: a path to a PEM file, or the PEM itself. Told apart by the armour, so a value beginning with -----BEGIN is read as the key rather than as a filename.
            pem_private:          ~ # Example: '%kernel.project_dir%/config/jwt/private.pem'

            # Verification key, same two spellings. A consumer needs this half; the private one cannot stand in for it.
            pem_public:           ~ # Example: '%kernel.project_dir%/config/jwt/public.pem'

            # Signing key as a JWK: a path to a JSON file, or the JSON itself. The only source for EdDSA, which has no PEM representation. What the document states — "alg", "kid", "use" — has to agree with what is configured here.
            jwk_private:          ~ # Example: '%kernel.project_dir%/config/jwt/private.jwk.json'

            # Verification key as a JWK, same two spellings. A document carrying "d" is refused: that is the private half, and the JWKS endpoint would publish it.
            jwk_public:           ~ # Example: '%kernel.project_dir%/config/jwt/public.jwk.json'

            # Passphrase for an encrypted private PEM. Use an env reference.
            pem_passphrase:       ~ # Example: '%env(JWT_KEY_PASSPHRASE)%'

            # The algorithm this key is bound to. A key verifies nothing else, and the algorithm decides what material the key must be.
            algorithm:            HS256 # One of "HS256"; "HS384"; "HS512"; "RS256"; "RS384"; "RS512"; "ES256"; "ES384"; "ES512"; "EdDSA"

            # Key id published in the token header. Required once two keys share an algorithm.
            kid:                  null

    # Named keys for reading encrypted tokens, referenced by name from a consumer's "jwe" block. Separate from `keys`: those sign and verify, these decrypt, and one key should not do both (RFC 7517 §4.2).
    jwe_keys:

        # Prototype
        name:

            # Shared secret, as raw bytes. Its length is fixed by "algorithm" — 16/24/32 bytes for the A128/A192/A256 names, and 32/48/64 for the CBC-HS family, which carries a MAC half (RFC 7518 §5.2.2.1). Use an env reference; a secret is bytes rather than text, so %env(base64:NAME)% is the spelling that survives one. The length cannot be checked while the container is built — the secret is still an env reference then — so a wrong one fails when the key is first built, which `jwt:config:check` is where to do deliberately.
            secret:               ~ # Required, Example: '%env(base64:JWT_JWE_SECRET)%'

            # What this key is made of. For key wrapping, the `alg` it wraps with (A128KW…A256GCMKW). For "dir", the key is the Content Encryption Key rather than something that wraps one, so name the `enc` it is a key for (A128GCM…A256CBC-HS512) — "dir" itself is not a value here, because no key is made of it.
            algorithm:            ~ # One of "A128KW"; "A192KW"; "A256KW"; "A128GCMKW"; "A192GCMKW"; "A256GCMKW"; "A128GCM"; "A192GCM"; "A256GCM"; "A128CBC-HS256"; "A192CBC-HS384"; "A256CBC-HS512", Required, Example: A256KW

            # Key id the sender names in the token's outer header. Required as soon as two of a consumer's keys share an algorithm — and for "dir" always, because a resolver falling back to the header's `alg` would be looking for a key bound to "dir", which no key is.
            kid:                  null

    # Named remote JWK Sets, referenced by name from anything that verifies: consumers, ID token registrations and security event consumers.
    remote_jwks:

        # Prototype
        name:

            # The issuer's `jwks_uri`. HTTPS only: fetching verification keys over a channel an attacker can rewrite defeats the point (RFC 8725 §3.10). Never taken from a token's `jku`. Give this or "discovery", not both.
            uri:                  null # Example: 'https://idp.example.com/.well-known/jwks.json'

            # The issuer identifier, for reading `jwks_uri` from its `/.well-known/openid-configuration` instead of hard-coding it (K7). HTTPS only, and the document has to name this same issuer back (OIDC Discovery §4.3). Use it when the provider may move the endpoint; use "uri" when it may not.
            discovery:            null # Example: 'https://idp.example.com'

            # Service id of a PSR-18 client. Symfony registers `psr18.http_client` once `psr/http-client` is installed and `framework.http_client` is enabled. Connection and response timeouts belong to the client: this bundle cannot impose a socket timeout on one it does not own. So does redirect policy — a client that follows a cross-origin redirect changes which host answered, which no check here can see.
            http_client:          psr18.http_client

            # Service id of a PSR-17 request factory. Null uses the client, which is right for Symfony's `psr18.http_client` — it is a factory as well — and wrong for a client that is not.
            request_factory:      null # Example: nyholm.psr7.psr17_factory

            # Service id of a PSR-6 cache pool, wrapped for the PSR-16 interface the resolver takes. This is the Symfony-shaped answer: `cache.app` is a pool.
            cache_pool:           null # Example: cache.app

            # Service id of a PSR-16 cache, used as it is. For an application that already has one; otherwise use "cache_pool".
            cache:                null # Example: app.jwks_cache

            # Seconds a fetched document is cached — the key set, and the discovery document that names it when "discovery" is used. The common path never touches the network. Zero is refused: it would fetch the set for every token.
            cache_ttl:            300

            # Shortest interval between refetches when a token names a `kid` the cached set does not have. Without it, a stream of tokens bearing unknown kids is an amplifier pointed at the issuer.
            min_refresh:          60

            # Responses larger than this are refused before parsing, so a hostile or broken endpoint cannot exhaust memory.
            max_body_bytes:       262144

    # Named issuers. Each mints tokens with exactly one key.
    issuers:

        # Prototype
        name:

            # Value of the `iss` claim, and what a consumer must expect.
            issuer:               ~ # Required

            # Name from the `keys` section. Its algorithm is the signing algorithm — a key is bound to one, so restating it here could only disagree.
            key:                  ~ # Required

            # Value of the `client_id` claim, required by RFC 9068 §2.2.
            client_id:            ~ # Required

            # Token lifetime in seconds. Short is the point: a bearer token cannot be recalled.
            ttl:                  900

            # Value of the `aud` claim.
            audience:             [] # Required

            # Static claims added to every token. A caller can override one; the profile's own claims cannot be overridden by either.
            claims:

                # Prototype
                name:                 ~

            # Seal this issuer's tokens: sign first, then encrypt the result as a JWE (RFC 7519 §5.2 nested JWT, §11.2 for the order). What the caller gets back is the sealed token; its `jti` and lifetime are unchanged, because encryption is what the token travels in rather than part of what it says. The recipient needs the matching key — a consumer of this application's own is configured with `consumers.*.jwe`.
            jwe:

                # Name from the `jwe_keys` section: the key the recipient will decrypt with. One key, not a list — a sender uses the key it was told to use.
                key:                  ~ # Required

                # JOSE `alg` written into the outer header: how the recipient gets the key the claims are encrypted with (RFC 7518 §4). "dir" uses the configured key as that key; the rest wrap a fresh one with it. Must be what the key is for — a wrapping key is bound to the `alg` it wraps with, and a "dir" key to the `enc` below.
                key_management:       ~ # One of "dir"; "A128KW"; "A192KW"; "A256KW"; "A128GCMKW"; "A192GCMKW"; "A256GCMKW", Required, Example: A256KW

                # JOSE `enc` written into the outer header: how the claims themselves are encrypted (RFC 7518 §5). All six are authenticated encryption; pick one the recipient allows.
                content_encryption:   ~ # One of "A128GCM"; "A192GCM"; "A256GCM"; "A128CBC-HS256"; "A192CBC-HS384"; "A256CBC-HS512", Required, Example: A256GCM

                # Claims copied into the outer header as well, where an intermediary has to read one without holding a key — `iss`, usually, so a gateway can route (RFC 7519 §5.3). The copy is read back out of the signed token, so it is the claim exactly; a receiver compares the two and must reject a token where they disagree. Nothing else about the token changes, and a name the token does not carry is not written. Empty is the default: a claim in the outer header is a claim nothing encrypted.
                replicated_claims:    []

                    # Example:
                    # - iss

    # Named consumers. A firewall names one through token_handler.
    consumers:

        # Prototype
        name:

            # The only `iss` this consumer accepts.
            issuer:               ~ # Required

            # Identifiers this resource server answers to. A token is accepted when its `aud` names any of them.
            audience:             [] # Required

            # How much of the token's `aud` has to be ours. "any" is RFC 7519 §4.1.3: the token is for us if it names us, whoever else it names too. "exclusive" also refuses a token addressed to anyone else, which is what RFC 9068 §3 asks of an access token — a token minted for several services only has to leak from the least careful one.
            audience_policy:      any # One of "any"; "exclusive"

            # Names from the `keys` section. Verification tries the key the token names, or the one bound to its algorithm. Optional only when "remote_jwks" is given; with both, these are tried first and the network is never touched for a key already here.
            keys:                 []

            # Name from the `remote_jwks` section: an issuer's published key set, fetched and cached rather than configured. Keys the issuer rotates to are picked up without a deploy.
            remote_jwks:          null # Example: partner_idp

            # JOSE `alg` values accepted. Anything else is refused before a signature is checked.
            allowed_algorithms:   [] # Required

            # Read this consumer's tokens as encrypted ones: a JWE wrapping the signed JWT (RFC 7519 §5.2 nested JWT). Written, it changes what arrives rather than what is checked — the outer layer is decrypted, and what comes out is verified by everything above, unchanged. A bare signed token is then refused, which is the point: an attacker who could strip the encryption and be believed would have been handed the confidentiality of a plaintext token.
            jwe:

                # Names from the `jwe_keys` section. The key the token's outer header names decrypts it, so several here is how an encryption key is rotated — the same shape as `keys`, and the same order: accept the new one, then ask the sender to use it.
                keys:                 [] # Required

                # JOSE `alg` values accepted in the outer header: how the sender and this consumer agree on the key the claims are encrypted with (RFC 7518 §4). "dir" means the configured key is that key; the rest wrap a fresh one.
                allowed_key_management: [] # Required

                    # Example:
                    # - A256KW

                # JOSE `enc` values accepted in the outer header: how the claims themselves are encrypted (RFC 7518 §5). All six are authenticated encryption, so this list keeps nothing dangerous out — it is here because the header of an arriving token must not be what decides how that token is read (RFC 8725 §3.1).
                allowed_content_encryption: [] # Required

                    # Example:
                    # - A256GCM

            # Protection space named in the `WWW-Authenticate` header of this consumer's entry point and scope denials (RFC 6750 §3). Null uses the consumer's name. Symfony has its own `access_token.realm` for the header it sends itself; keep the two equal. A literal, not an env reference: the value is validated, which is what stops a quote or a newline from costing the header, and Symfony refuses to validate a placeholder.
            realm:                null # Example: api

            # Clock-skew tolerance in seconds for exp/nbf/iat. The ceiling is the library's.
            leeway:               0

            # The `typ` this consumer expects, for a token whose posture is this application's rather than a standard. Naming one verifies the token as a plain JWT with the rules below instead of through the RFC 9068 access-token profile: same keys, algorithms, issuer, audience, leeway and clock, and none of the profile's own required claims. Omit it — the default — for the RFC 9068 posture. RFC 7515 §4.1.9 puts the bare form on the wire, so give it without the "application/" prefix.
            token_type:           null # Example: vnd.acme.session+jwt

            # Claims a token must carry, for a consumer that names a `token_type`. Only the presence is checked; what a value means is the application's. Left out, it is `["exp"]`: the library checks `exp`, `nbf` and `iat` where a token carries them and nowhere else, so a posture requiring none of them would accept a credential that never stops being valid. A list of your own replaces that — and one omitting `exp` needs `max_token_age` to bound the token instead.
            required_claims:      []

                # Examples:
                # - exp
                # - sub
                # - session_id

            # Refuse a token older than this many seconds, counted from `iat`, however long its `exp` says it lives. A ceiling of your own on an issuer's generosity: a leaked token stops working when this runs out rather than when they decided it should. Off unless set, and `leeway` widens it as it widens every other dated check.
            max_token_age:        null # Example: '300'

            # Where this consumer asks whether a token has been withdrawn since it was issued. Configured, it costs a lookup per request; unconfigured, nothing is asked and nothing is registered.
            denylist:

                # Service id implementing TokenDenylistInterface. For a store of your own — the shipped one is a cache, and a cache flush forgets every revocation.
                service:              null # Example: app.token_denylist

                # Service id of a PSR-6 cache pool, wrapped for the PSR-16 interface the shipped denylist takes. `cache.app` is a pool.
                cache_pool:           null # Example: cache.app

                # Service id of a PSR-16 cache, used as it is.
                cache:                null # Example: app.simple_cache

                # Prefix for the cache keys, so revocations do not collide with the rest of the pool. The rest of the key is a hash of the `jti`. PSR-16 §6 reserves {}()/\@: in keys, so those are refused here rather than by the store on every request.
                prefix:               medzuch_jwt.revoked.
            user:

                # Where the user comes from. "provider" asks the firewall's user provider, which is right when a store is the authority. "claims" builds the user from the token, which is right when the issuer is — a resource server verifying a third party's tokens usually has nothing to look up. "custom" hands the claims to a service of yours.
                mode:                 provider # One of "provider"; "claims"; "custom"

                # Claim whose value identifies the user. In "provider" mode it is what the user provider is asked for; mode "custom" ignores it, because the factory names the user it builds.
                identity_claim:       sub

                # Service id implementing JwtUserFactoryInterface. Required by mode "custom", and refused by the others, which have their own answer.
                factory:              null # Example: app.jwt_user_factory

                # How the token's claims become roles. Only mode "claims" reads this: a user provider brings its own roles, and a custom factory decides for itself.
                roles:

                    # Claim carrying what the token grants — "scope" (RFC 6749 §3.3), "roles", "groups" or whatever your issuer sends. A list or a delimited string; both are read.
                    claim:                null # Example: scope

                    # Delimiter, when the claim is a string. A space is what `scope` uses. Null treats a string claim as one whole value.
                    separator:            ' '

                    # Prepended to each value, because Symfony's access rules speak in ROLE_*. Set it to an empty string if your issuer already sends them prefixed.
                    prefix:               ROLE_

                    # Roles every verified token gets, whatever it claims. Empty unless set: a baseline like ROLE_USER is granted only if you ask for it, and nothing invents one.
                    defaults:             []

    # Named token extractors. Reference them from a firewall's `access_token.token_extractors`, beside Symfony's own security.access_token_extractor.header, .query_string and .request_body.
    token_extractors:

        # Prototype
        name:

            # Name of the cookie carrying the token. A `__Host-` prefix is worth having: it makes the browser refuse the cookie unless it is Secure, path-wide and unscoped to a domain, which stops a subdomain from setting one.
            cookie:               ~ # Required, Example: __Host-jwt

            # Ignore the cookie when the browser reports the request as cross-site (`Sec-Fetch-Site`). Defence in depth against CSRF, not a defence: a request without the header — an API client, an older browser — is not judged, so state-changing routes still need their own protection.
            same_site_only:       false

    # Named OIDC relying-party registrations. Each verifies ID tokens from one provider, for one client.
    id_tokens:

        # Prototype
        name:

            # The only `iss` accepted, exactly as the provider publishes it.
            issuer:               ~ # Required, Example: 'https://idp.example.com'

            # This application's client id at the provider. It is the audience an ID token must name, and the `azp` it must name when it names more than one (OIDC Core §3.1.3.7).
            client_id:            ~ # Required, Example: '%env(OIDC_CLIENT_ID)%'

            # Names from the `keys` section. Optional only when "remote_jwks" is given; with both, these are tried first.
            keys:                 []

            # Name from the `remote_jwks` section. The ordinary way to verify a provider's ID tokens: they rotate their keys on their own schedule.
            remote_jwks:          null # Example: partner_idp

            # JOSE `alg` values accepted. Anything else is refused before a signature is checked.
            allowed_algorithms:   [] # Required

            # Clock-skew tolerance in seconds for exp/nbf/iat. The ceiling is the library's.
            leeway:               0

    # RFC 8417 Security Event Tokens: `issuers` transmits them, `consumers` receives them. Neither is a bearer credential, so neither is wired into a firewall.
    security_events:

        # Named event streams this application transmits. Each signs with one key, as one issuer.
        issuers:

            # Prototype
            name:

                # The `iss` every SET from this stream carries. Receivers pin it, so it is the identifier they were told to expect.
                issuer:               ~ # Required, Example: 'https://idp.example.com'

                # Name from the `keys` section, whose private half signs. A key with only a public half is refused at container build.
                key:                  ~ # Required, Example: signing

                # The `aud` every SET from this stream names — the receivers subscribed to it. Optional: RFC 8417 §2.2 only RECOMMENDS the claim, and a caller can name it per SET instead.
                audience:             []

        # Named transmitters this application accepts SETs from. Each verifies deliveries from one issuer.
        consumers:

            # Prototype
            name:

                # The only `iss` accepted, exactly as the transmitter publishes it.
                issuer:               ~ # Required, Example: 'https://idp.example.com'

                # Names from the `keys` section. Optional only when "remote_jwks" is given; with both, these are tried first.
                keys:                 []

                # Name from the `remote_jwks` section. The ordinary way to verify a transmitter's SETs: they rotate their keys on their own schedule.
                remote_jwks:          null # Example: partner_idp

                # JOSE `alg` values accepted. Anything else is refused before a signature is checked.
                allowed_algorithms:   [] # Required

                # The `aud` a SET must name to be for this receiver. Null accepts whatever it names, which is right for a stream with one subscriber and wrong for a transmitter feeding several.
                audience:             null # Example: 'https://rp.example.com'

                # Clock-skew tolerance in seconds for nbf/iat. There is no exp on a SET (RFC 8417 §4.1.4), so this forgives a transmitter whose clock runs ahead, and nothing else.
                leeway:               0

    # Public keys to publish as a JWK Set. The application routes to medzuch_jwt.jwks_controller itself; where the document lives is its decision.
    jwks:

        # Names from the `keys` section. Only verification halves are published, and never a shared secret.
        keys:                 []

        # Seconds a relying party may cache the document. The response carries an ETag, so zero means revalidate — a conditional request gets 304 — rather than refetch. A rotation needs neither: an accepted key stays accepted for as long as it is configured.
        cache_max_age:        300

    # This application's own RFC 8414 metadata document. The application routes to medzuch_jwt.metadata_controller itself, at whichever well-known path it means — the document differs by what it carries, not by how it is served.
    metadata:

        # The issuer identifier this document speaks for, which a reader checks the document against (RFC 8414 §2, OIDC Discovery §4.3). HTTPS only. Omit the whole section to publish nothing; blankness and scheme are checked at container build.
        issuer:               null # Example: '%env(APP_URL)%'

        # Where this application serves its JWK Set — the route it points medzuch_jwt.jwks_controller at. HTTPS only. Optional per RFC 8414, and omitting it leaves a reader with an issuer whose keys it cannot find.
        jwks_uri:             null # Example: '%env(APP_URL)%/.well-known/jwks.json'

        # Every other member, verbatim: response_types_supported (which RFC 8414 §2 requires), the endpoints, the grant types — all of it describes an authorization server this bundle is not, so none of it is invented here. "issuer" and "jwks_uri" are refused, being the two above.
        extra:                []

        # Seconds a reader may cache the document. The response carries an ETag, so zero means revalidate rather than refetch.
        cache_max_age:        300
```
