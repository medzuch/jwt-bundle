# Upgrading

The [changelog](CHANGELOG.md) says what changed. This file says what you have to *do* about it,
version to version, and nothing else — if a release asks nothing of you, that is what its
section says.

**Configuration keys are public API**, and from 1.0.0 a rename or a removal is a major release
with a deprecation path ([`BACKWARD-COMPATIBILITY.md`](BACKWARD-COMPATIBILITY.md) says what else
is covered). No configuration key has been removed or renamed in any release so far: every one
has been additive, with new sections inert until configured, so what the notes below carry is
behaviour an application already running could notice rather than configuration it must
rewrite.

## 1.0.0 → 1.1.0

**Almost nothing in your configuration has to change**, and every section this release adds is
absent until you write it: `jwe_keys`, `dispatchers`, `id_token_issuers`, `metadata`,
`security_events`, `consumers.*.jwe`, `issuers.*.jwe` and `remote_jwks.*.discovery`. Three things
are worth knowing anyway, and only the `secevent+jwt` one can ask anything of a file you have
already written.

**An access token is no longer accepted as an ID token.** `IdTokenVerifier::verify()` refuses a
token whose header says `typ: at+jwt` before it checks anything else. OIDC asks for no `typ` on
an ID token, so nothing had stopped an access token from verifying as one wherever its `aud`
happened to equal the registration's `client_id` — a credential minted for an API, presented at
a login callback, logging somebody in. No provider labels an ID token as an access token, so
this refuses nothing a real relying party was accepting; if your identity provider does label
them that way, it is the provider that has to change.

**`secevent+jwt` is now a reserved `token_type`.** 1.0 refused two spellings on a consumer —
`at+jwt` and `JWT` — because each names a profile the bundle verifies rather than a type of your
own. C8 added the third: a Security Event Token is configured under `security_events`, not on a
firewall. A 1.0 configuration that named `consumers.*.token_type: secevent+jwt` therefore stops
booting, with a message saying where SETs belong. Nobody should have written it — that is what
the refusal is for — but it is the one new *value* that can turn a configuration that booted into
one that does not.

**`log_levels` gained two categories**, `decrypted` and `decryption_failed`. They are read only
where a consumer configures `jwe`, and each keeps the library's default until you set it, so an
existing `log_levels` block means what it meant.

Everything else is a new section you have not written yet. The README has a walkthrough for
each: [encrypted tokens](README.md#reading-an-encrypted-token) and
[minting them](README.md#minting-an-encrypted-token),
[several issuers behind one firewall](README.md#several-issuers-behind-one-firewall),
[issuing ID tokens](README.md#issuing-id-tokens-oidc-provider),
[publishing your own metadata](README.md#publishing-your-own-metadata),
[discovering an issuer's keys](README.md#discovering-an-issuers-keys) and
[security events](README.md#sending-and-receiving-security-events).

## 0.3.0 → 1.0.0

**Nothing in your configuration has to change**, and every option this release adds is absent
until you write it: `token_extractors`, `log_levels`, and `consumers.*.denylist`,
`.user`, `.realm`, `.max_token_age`, `.token_type` and `.required_claims`. Five things are
worth knowing anyway.

**The RFC 6750 refusal answers are opt-in.** `medzuch_jwt.entry_point.<name>` and
`medzuch_jwt.access_denied.<name>` exist for every consumer, but a firewall answers as it did
in 0.3 until it names them. Wiring them changes what an unauthenticated request and a
scope denial carry:

```diff
 security:
     firewalls:
         api:
+            entry_point: medzuch_jwt.entry_point.api
+            access_denied_handler: medzuch_jwt.access_denied.api
             access_token:
                 token_handler: medzuch_jwt.handler.api
```

See [What a refusal tells the caller](README.md#what-a-refusal-tells-the-caller) for the two
realms that then want to agree.

**The scope voter is registered unconditionally**, and answers `SCOPE_*` attributes and nothing
else. An application whose access rules never say `SCOPE_*` never asks it a question. Two cases
do change:

- If you already answer `SCOPE_*` with a voter of your own **and** have moved off the default
  `affirmative` decision strategy, this voter now votes beside yours: under `unanimous` or
  `consensus` its denial counts. Under `affirmative` it cannot override your grant.
- It reads scopes off the *user*, which must implement `ProvidesScopes`. `user.mode: claims`
  builds one; in the default `provider` mode your own user class decides, and one that says
  nothing about scopes means every `SCOPE_*` check is denied. That was already the answer in
  0.3, where nothing voted on the attribute and Symfony denies when every voter abstains — it
  changes only under `allow_if_all_abstain: true`, where an unanswered `SCOPE_*` used to be
  granted and is now decided.

**`IssuedToken` takes a third constructor argument**, `$jti`. The class is a return value that
nothing outside the bundle constructs in ordinary use, so this reaches test doubles and
fixtures rather than application code:

```diff
-new IssuedToken($value, 3600);
+new IssuedToken($value, 3600, $jti);
```

**Most of `src/` is now marked `@internal`**, which static analysis will start saying out loud.
`AccessTokenHandler`, `AccessTokenSuccessHandler`, `BearerEntryPoint`, `InsufficientScopeHandler`,
`CookieTokenExtractor`, `ScopeVoter`, `CacheTokenDenylist`, `JwksController` and the five command
classes were never the documented way to reach any of that, and nothing about them changed — but
code that imported or type-hinted one will now get an `@internal` notice from PHPStan or Psalm.

The fix is the same in every case: name the service id or implement the interface.
`medzuch_jwt.handler.<consumer>` instead of `AccessTokenHandler`,
`medzuch_jwt.denylist.<consumer>` and `TokenDenylistInterface` instead of `CacheTokenDenylist`,
the command's name instead of its class. [`BACKWARD-COMPATIBILITY.md`](BACKWARD-COMPATIBILITY.md)
is the full list of what is reachable and how.

**The profiler panel decorates the handler your firewall calls**, wherever
`framework.profiler` is enabled — so a `dev` container now shows a `TraceableAccessTokenHandler`
where `debug:container` showed the handler itself. What it decorates is the copy SecurityBundle
builds for the firewall (`security.access_token_handler.<firewall>`), never
`medzuch_jwt.handler.<name>`, so a decoration of your own on that service is untouched. With the
profiler off — `prod`, normally — neither the decorator nor the collector is registered, and
nothing runs.

## 0.2.0 → 0.3.0

**Nothing to do.** Federation is entirely additive: `remote_jwks`, `id_tokens` and
`consumers.*.audience_policy` are inert until configured, no default changed, and nothing was
removed or renamed.

One relaxation, which can only ever accept configuration that used to be refused:
`consumers.<name>.keys` is no longer required, because a consumer may verify entirely against a
remote set. A consumer naming neither `keys` nor `remote_jwks` is still refused, now with a
message naming both.

And one check that stops being made: **with `remote_jwks` configured, "every allowed algorithm
has a key behind it" is not enforced at build**. The issuer publishes its algorithms at runtime
and may rotate to one you have never seen, so the question has no build-time answer. Without a
remote set the check is unchanged. The practical consequence is that a typo in
`allowed_algorithms` on a remote-set consumer is found by a token being refused rather than by
the container failing to build.

## 0.1.0 → 0.2.0

**One configuration change, and only if you wrote a redundant entry.** A consumer naming the
same key twice is now refused at container build:

```diff
 consumers:
     api:
-        keys: [default, default]
+        keys: [default]
```

It booted in 0.1.0 and did nothing: resolution is first-match-wins, so the second copy was
unreachable. If your configuration has one, deleting it changes no behaviour.

**Key services answer by role.** `medzuch_jwt.key.<name>.signing` and
`medzuch_jwt.key.<name>.verification` are the ids to inject. For a shared secret — the only
kind 0.1.0 had — both are aliases to `medzuch_jwt.key.<name>`, so code injecting the old id
keeps working; for a keypair only the half you configured exists, and the old id names the
private half where there is one.

**The `kid` ambiguity check moved** from the whole configuration to each consumer's key set,
which is the only place the ambiguity can bite — the resolver only ever sees the keys of the
consumer doing the verifying. Nothing to do: the check only became narrower. It had to, for the
asymmetric keys 0.2.0 introduces, since a private entry and a public entry that are two halves
of one keypair share an algorithm and a `kid` precisely because they are the same key — which
the global form would have refused.
