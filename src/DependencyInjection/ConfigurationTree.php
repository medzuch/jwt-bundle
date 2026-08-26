<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\DependencyInjection;

use Medzuch\Jwt\Diagnostics\LogLevels;
use Medzuch\Jwt\Jwt\ValidatorBuilder;
use Medzuch\JwtBundle\Algorithm\SigningAlgorithms;
use Medzuch\JwtBundle\Issuer\ReservedClaims;
use Medzuch\JwtBundle\Security\Http\Challenge;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/**
 * The `medzuch_jwt` configuration tree.
 *
 * Every node's `info()` is what `config:dump-reference` prints, so this class
 * doubles as the reference an application reads from its own console. That is
 * why those strings stay tutorial where the rest of `src/` does not.
 *
 * @internal
 */
final class ConfigurationTree
{
    public static function define(DefinitionConfigurator $definition): void
    {
        $root = $definition->rootNode();

        // Narrowed rather than assumed: `rootNode()` declares NodeDefinition on
        // every supported major and only Symfony 8 annotates a conditional
        // return type on top of it. DEC-2 keeps `treatPhpDocTypesAsCertain` off
        // for this line.
        \assert($root instanceof ArrayNodeDefinition);

        $children = $root->children();

        self::configureGlobals($children);
        self::configureKeys($children);
        self::configureRemoteJwks($children);
        self::configureIssuers($children);
        self::configureConsumers($children);
        self::configureTokenExtractors($children);
        self::configureIdTokens($children);
        self::configureJwks($children);
    }

    /**
     * The diagnostics this bundle can emit, as a configuration option, the
     * constructor argument it sets on {@see LogLevels}, what it covers, and
     * the level somebody plausibly wants — which is not the same one for every
     * category: raising an accepted token to `info` is auditing, raising a
     * refusal to `warning` is alerting.
     *
     * Five of the library's seven. The other two are JWE — a token decrypted,
     * and one that would not decrypt — and nothing here issues or consumes an
     * encrypted token yet (C12/I8), so an option for them would be a level
     * nothing is ever emitted at.
     */
    public const LOG_LEVELS = [
        'accepted' => ['accepted', 'A token that passed every check. `debug` by default, because on a busy API this is one line per request.', 'info'],
        'verification_failed' => ['verificationFailed', 'Signature, algorithm allowlist, or key resolution while verifying — an integrity problem rather than a policy one. `warning` by default.', 'error'],
        'claim_rejected' => ['claimRejected', 'A properly signed token whose claims are refused: expired, not yet valid, wrong issuer or audience, a missing required claim, a profile rule. `notice` by default, because this is the ordinary cost of short lifetimes.', 'info'],
        'key_resolution' => ['keyResolution', 'A remote JWK Set fetched, served from cache, or refreshed. `debug` by default.', 'info'],
        'key_resolution_failed' => ['keyResolutionFailed', 'A remote JWK Set that could not be fetched or parsed — an outage on one side or the other. `warning` by default.', 'critical'],
    ];

    /** Named because the registration compares against it to catch a prefix nothing would read. */
    public const DEFAULT_DENYLIST_PREFIX = 'medzuch_jwt.revoked.';

    private static function configureGlobals(NodeBuilder $children): void
    {
        $children->scalarNode('clock')
            ->defaultNull()
            ->info('Service id of a PSR-20 clock. Null uses the library\'s SystemClock.')
            ->example('app.frozen_clock')
            ->validate()
                ->ifTrue(static fn(mixed $value): bool => null !== $value && (!\is_string($value) || '' === trim($value)))
                ->thenInvalid('medzuch_jwt.clock must be a non-empty service id, got %s')
            ->end();

        $levels = $children->arrayNode('log_levels')
            ->addDefaultsIfNotSet()
            ->info('The PSR-3 level each kind of diagnostic is emitted at. The library decides the level; your logger decides whether to record it — so this is how a resource server stops paying for a line per accepted token, or starts alerting on refusals. Unset, each keeps the library\'s default. Read only where a `logger` is configured.')
            ->children();

        foreach (self::LOG_LEVELS as $option => [, $info, $example]) {
            $levels->scalarNode($option)
                ->defaultNull()
                ->info($info)
                ->example($example)
                ->validate()
                    ->ifTrue(static fn(mixed $value): bool => null !== $value && !in_array($value, LogLevels::all(), true))
                    ->thenInvalid('medzuch_jwt.log_levels.' . $option . ' must be one of the eight PSR-3 levels (' . implode(', ', LogLevels::all()) . '). Got %s')
                ->end()
                ->end();
        }

        $levels->end();

        $children->scalarNode('logger')
            ->defaultNull()
            ->info('Service id of a PSR-3 logger. Null disables logging entirely.')
            ->example('monolog.logger.jwt')
            ->validate()
                ->ifTrue(static fn(mixed $value): bool => null !== $value && (!\is_string($value) || '' === trim($value)))
                ->thenInvalid('medzuch_jwt.logger must be a non-empty service id, got %s')
            ->end();
    }

    private static function configureKeys(NodeBuilder $children): void
    {
        $key = $children->arrayNode('keys')
            ->info('Named keys, referenced by name from consumers and issuers.')
            ->useAttributeAsKey('name')
            ->arrayPrototype()
            ->children();

        self::declareKeySource(
            $key,
            'hmac',
            'Shared secret, at least 32/48/64 bytes for HS256/384/512 (RFC 8725 §3.5). Use an env reference; %env(base64:NAME)% decodes a base64 secret. The length cannot be checked at build: the secret stays an env reference so it never reaches a container parameter, so a short one fails when the key is first used.',
            '%env(JWT_SECRET)%',
        );

        self::declareKeySource(
            $key,
            'pem_private',
            'Signing key: a path to a PEM file, or the PEM itself. Told apart by the armour, so a value beginning with -----BEGIN is read as the key rather than as a filename.',
            '%kernel.project_dir%/config/jwt/private.pem',
        );

        self::declareKeySource(
            $key,
            'pem_public',
            'Verification key, same two spellings. A consumer needs this half; the private one cannot stand in for it.',
            '%kernel.project_dir%/config/jwt/public.pem',
        );

        self::declareKeySource(
            $key,
            'jwk_private',
            'Signing key as a JWK: a path to a JSON file, or the JSON itself. The only source for EdDSA, which has no PEM representation. What the document states — "alg", "kid", "use" — has to agree with what is configured here.',
            '%kernel.project_dir%/config/jwt/private.jwk.json',
        );

        self::declareKeySource(
            $key,
            'jwk_public',
            'Verification key as a JWK, same two spellings. A document carrying "d" is refused: that is the private half, and the JWKS endpoint would publish it.',
            '%kernel.project_dir%/config/jwt/public.jwk.json',
        );

        self::declareKeySource(
            $key,
            'pem_passphrase',
            'Passphrase for an encrypted private PEM. Use an env reference.',
            '%env(JWT_KEY_PASSPHRASE)%',
        );

        $key->enumNode('algorithm')
            ->values(SigningAlgorithms::names())
            ->defaultValue('HS256')
            ->info('The algorithm this key is bound to. A key verifies nothing else, and the algorithm decides what material the key must be.')
            ->end();

        $key->scalarNode('kid')
            ->defaultNull()
            ->info('Key id published in the token header. Required once two keys share an algorithm.')
            ->validate()
                ->ifTrue(static fn(mixed $value): bool => '' === $value)
                ->thenInvalid('A key\'s "kid" cannot be the empty string; omit it instead.')
            ->end()
            ->end();
    }

    /**
     * A key set the bundle does not hold: an issuer publishes it, the
     * application fetches it. Named at the top level rather than spelled out
     * inside a consumer, because two consumers of the same identity provider
     * are the ordinary case and they should share one cache entry and one
     * refresh window, not race each other for them.
     */
    private static function configureRemoteJwks(NodeBuilder $children): void
    {
        $set = $children->arrayNode('remote_jwks')
            ->info('Named remote JWK Sets, referenced by name from consumers.')
            ->useAttributeAsKey('name')
            ->arrayPrototype()
            ->children();

        $set->scalarNode('uri')
            ->isRequired()
            ->cannotBeEmpty()
            ->info('The issuer\'s `jwks_uri`. HTTPS only: fetching verification keys over a channel an attacker can rewrite defeats the point (RFC 8725 §3.10). Never taken from a token\'s `jku`.')
            ->example('https://idp.example.com/.well-known/jwks.json')
            ->end();

        $set->scalarNode('http_client')
            ->defaultValue('psr18.http_client')
            ->cannotBeEmpty()
            ->info('Service id of a PSR-18 client. Symfony registers `psr18.http_client` once `psr/http-client` is installed and `framework.http_client` is enabled. Connection and response timeouts belong to the client: this bundle cannot impose a socket timeout on one it does not own.')
            ->end();

        self::declareOptionalName(
            $set,
            'request_factory',
            'Service id of a PSR-17 request factory. Null uses the client, which is right for Symfony\'s `psr18.http_client` — it is a factory as well — and wrong for a client that is not.',
            'nyholm.psr7.psr17_factory',
        );

        self::declareOptionalName($set, 'cache_pool', 'Service id of a PSR-6 cache pool, wrapped for the PSR-16 interface the resolver takes. This is the Symfony-shaped answer: `cache.app` is a pool.', 'cache.app');
        self::declareOptionalName($set, 'cache', 'Service id of a PSR-16 cache, used as it is. For an application that already has one; otherwise use "cache_pool".', 'app.jwks_cache');

        // The library refuses zero for all three, and it is right to: a
        // lifetime of zero is a fetch per token, and a refresh window of zero
        // is the amplifier the window exists to prevent. `min(1)` says so here
        // rather than letting a configuration the tree accepted fail inside a
        // service factory.
        $set->integerNode('cache_ttl')
            ->defaultValue(300)
            ->min(1)
            ->info('Seconds the fetched document is cached. The common path never touches the network. Zero is refused: it would fetch the set for every token.')
            ->end();

        $set->integerNode('min_refresh')
            ->defaultValue(60)
            ->min(1)
            ->info('Shortest interval between refetches when a token names a `kid` the cached set does not have. Without it, a stream of tokens bearing unknown kids is an amplifier pointed at the issuer.')
            ->end();

        $set->integerNode('max_body_bytes')
            ->defaultValue(256 * 1024)
            ->min(1)
            ->info('Responses larger than this are refused before parsing, so a hostile or broken endpoint cannot exhaust memory.')
            ->end();
    }

    /**
     * An optional reference to something named elsewhere — a service id, or a
     * name from another section.
     *
     * `cannotBeEmpty()` is not what these want: null is their default and
     * their way of saying "not configured", and `cannotBeEmpty()` refuses it
     * when written out, so `remote_jwks: ~` would fail with a message about
     * emptiness rather than being the no-op it reads as. What is refused is a
     * blank string, which is a name nobody meant to write.
     */
    private static function declareOptionalName(NodeBuilder $node, string $name, string $info, string $example): void
    {
        $node->scalarNode($name)
            ->defaultNull()
            ->info($info)
            ->example($example)
            ->validate()
                ->ifTrue(static fn(mixed $value): bool => is_string($value) && '' === trim($value))
                ->thenInvalid('medzuch_jwt.' . $name . ' cannot be blank; omit it instead. Got %s')
            ->end()
            ->end();
    }

    /**
     * Named token extractors, for the firewall to reference by service id.
     *
     * Only the cookie one lives here: Symfony ships extractors for the
     * `Authorization` header, the query string and a form-encoded body, and a
     * fourth spelling of those would be a name to learn for no gain. What it
     * does not ship is the one a browser needs, which is why this exists.
     */
    private static function configureTokenExtractors(NodeBuilder $children): void
    {
        $extractor = $children->arrayNode('token_extractors')
            ->info('Named token extractors. Reference them from a firewall\'s `access_token.token_extractors`, beside Symfony\'s own security.access_token_extractor.header, .query_string and .request_body.')
            ->useAttributeAsKey('name')
            ->arrayPrototype()
            ->children();

        $extractor->scalarNode('cookie')
            ->isRequired()
            ->cannotBeEmpty()
            ->info('Name of the cookie carrying the token. A `__Host-` prefix is worth having: it makes the browser refuse the cookie unless it is Secure, path-wide and unscoped to a domain, which stops a subdomain from setting one.')
            ->example('__Host-jwt')
            ->validate()
                // A name outside the RFC 6265 §4.1.1 token set is one no
                // browser will ever send under, so the extractor would sit
                // there matching nothing — a build error says that now instead
                // of leaving an authentication that never fires.
                ->ifTrue(static fn(mixed $value): bool => is_string($value) && 1 !== preg_match('/^[!#$%&\'*+\-.^_`|~0-9A-Za-z]+$/', $value))
                // The character list is escaped for sprintf, which thenInvalid()
                // runs the message through: a bare %& is a format specifier.
                ->thenInvalid('A cookie name must be an RFC 6265 §4.1.1 token: letters, digits and !#$%%&\'*+-.^_`|~, with no spaces or separators. A name outside that set is never sent by a browser. Got %s')
            ->end()
            ->end();

        $extractor->booleanNode('same_site_only')
            ->defaultFalse()
            ->info('Ignore the cookie when the browser reports the request as cross-site (`Sec-Fetch-Site`). Defence in depth against CSRF, not a defence: a request without the header — an API client, an older browser — is not judged, so state-changing routes still need their own protection.')
            ->end();
    }

    /**
     * An OIDC relying-party registration: which provider, which client, and
     * what to verify their ID tokens with.
     *
     * Separate from `consumers` rather than a mode of it, because the two
     * produce different things. A consumer is wired into a firewall; an ID
     * token is not a bearer credential and gets no handler, so putting them in
     * one section would make the wrong wiring a one-word change.
     */
    private static function configureIdTokens(NodeBuilder $children): void
    {
        $idToken = $children->arrayNode('id_tokens')
            ->info('Named OIDC relying-party registrations. Each verifies ID tokens from one provider, for one client.')
            ->useAttributeAsKey('name')
            ->arrayPrototype()
            ->children();

        $idToken->scalarNode('issuer')
            ->isRequired()
            ->cannotBeEmpty()
            ->info('The only `iss` accepted, exactly as the provider publishes it.')
            ->example('https://idp.example.com')
            ->end();

        $idToken->scalarNode('client_id')
            ->isRequired()
            ->cannotBeEmpty()
            ->info('This application\'s client id at the provider. It is the audience an ID token must name, and the `azp` it must name when it names more than one (OIDC Core §3.1.3.7).')
            ->example('%env(OIDC_CLIENT_ID)%')
            ->end();

        $keys = $idToken->arrayNode('keys');
        $keys->info('Names from the `keys` section. Optional only when "remote_jwks" is given; with both, these are tried first.');
        $keys->scalarPrototype()->cannotBeEmpty()->end();
        self::rejectMaps($keys, 'id_tokens.*.keys');

        self::declareOptionalName(
            $idToken,
            'remote_jwks',
            'Name from the `remote_jwks` section. The ordinary way to verify a provider\'s ID tokens: they rotate their keys on their own schedule.',
            'partner_idp',
        );

        $algorithms = $idToken->arrayNode('allowed_algorithms');
        $algorithms->info('JOSE `alg` values accepted. Anything else is refused before a signature is checked.');
        $algorithms->enumPrototype()->values(SigningAlgorithms::names())->end();
        $algorithms->isRequired();
        $algorithms->requiresAtLeastOneElement();
        self::rejectMaps($algorithms, 'id_tokens.*.allowed_algorithms');

        $idToken->integerNode('leeway')
            ->defaultValue(0)
            ->min(0)
            ->max(ValidatorBuilder::LEEWAY_CEILING_SECONDS)
            ->info('Clock-skew tolerance in seconds for exp/nbf/iat. The ceiling is the library\'s.')
            ->end();
    }

    private static function configureIssuers(NodeBuilder $children): void
    {
        $issuer = $children->arrayNode('issuers')
            ->info('Named issuers. Each mints tokens with exactly one key.')
            ->useAttributeAsKey('name')
            ->arrayPrototype()
            ->children();

        $issuer->scalarNode('issuer')
            ->isRequired()
            ->cannotBeEmpty()
            ->info('Value of the `iss` claim, and what a consumer must expect.')
            ->end();

        $issuer->scalarNode('key')
            ->isRequired()
            ->cannotBeEmpty()
            ->info('Name from the `keys` section. Its algorithm is the signing algorithm — a key is bound to one, so restating it here could only disagree.')
            ->end();

        $issuer->scalarNode('client_id')
            ->isRequired()
            ->cannotBeEmpty()
            ->info('Value of the `client_id` claim, required by RFC 9068 §2.2.')
            ->end();

        $issuer->integerNode('ttl')
            ->defaultValue(900)
            ->min(1)
            ->info('Token lifetime in seconds. Short is the point: a bearer token cannot be recalled.')
            ->end();

        $audience = $issuer->arrayNode('audience');
        $audience->info('Value of the `aud` claim.');
        $audience->beforeNormalization()->castToArray()->end();
        $audience->scalarPrototype()->cannotBeEmpty()->end();
        $audience->isRequired();
        $audience->requiresAtLeastOneElement();
        self::rejectMaps($audience, 'issuers.*.audience');

        $claims = $issuer->arrayNode('claims');
        $claims->info('Static claims added to every token. A caller can override one; the profile\'s own claims cannot be overridden by either.');
        $claims->normalizeKeys(false);
        $claims->useAttributeAsKey('name');
        $claims->variablePrototype()->end();
        // The library routes registered claims through typed setters and
        // refuses them here, so this configuration would build a green
        // container and throw on the first token minted.
        $claims->validate()
            ->ifTrue(static fn(mixed $value): bool => is_array($value) && [] !== array_intersect(array_keys($value), ReservedClaims::REGISTERED))
            ->thenInvalid(sprintf(
                'Static claims cannot include the registered claims %s — they are set from configuration (`issuer`, `audience`, `ttl`) or by the profile. Got %%s',
                '"' . implode('", "', ReservedClaims::REGISTERED) . '"',
            ))
            ->end();
    }

    private static function configureJwks(NodeBuilder $children): void
    {
        $jwks = $children->arrayNode('jwks')
            ->info('Public keys to publish as a JWK Set. The application routes to medzuch_jwt.jwks_controller itself; where the document lives is its decision.')
            ->addDefaultsIfNotSet();

        $jwksChildren = $jwks->children();

        $keys = $jwksChildren->arrayNode('keys');
        $keys->info('Names from the `keys` section. Only verification halves are published, and never a shared secret.');
        $keys->scalarPrototype()->cannotBeEmpty()->end();
        $keys->defaultValue([]);
        self::rejectMaps($keys, 'jwks.keys');

        $jwksChildren->integerNode('cache_max_age')
            ->defaultValue(300)
            ->min(0)
            ->info('Seconds a relying party may cache the document. The response carries an ETag, so zero means revalidate — a conditional request gets 304 — rather than refetch. A rotation needs neither: an accepted key stays accepted for as long as it is configured.')
            ->end();
    }

    private static function configureConsumers(NodeBuilder $children): void
    {
        $consumer = $children->arrayNode('consumers')
            ->info('Named consumers. A firewall names one through token_handler.')
            ->useAttributeAsKey('name')
            ->arrayPrototype()
            ->children();

        $consumer->scalarNode('issuer')
            ->isRequired()
            ->cannotBeEmpty()
            ->info('The only `iss` this consumer accepts.')
            ->end();

        // Each node is held in a variable rather than chained: NodeDefinition
        // methods return the base type or a nullable parent, so a fluent chain
        // loses ArrayNodeDefinition after the first hop.
        $audience = $consumer->arrayNode('audience');
        $audience->info('Identifiers this resource server answers to. A token is accepted when its `aud` names any of them.');
        $audience->beforeNormalization()->castToArray()->end();
        $audience->scalarPrototype()->cannotBeEmpty()->end();
        $audience->isRequired();
        $audience->requiresAtLeastOneElement();
        self::rejectMaps($audience, 'consumers.*.audience');

        $consumer->enumNode('audience_policy')
            ->values(['any', 'exclusive'])
            ->defaultValue('any')
            ->info('How much of the token\'s `aud` has to be ours. "any" is RFC 7519 §4.1.3: the token is for us if it names us, whoever else it names too. "exclusive" also refuses a token addressed to anyone else, which is what RFC 9068 §3 asks of an access token — a token minted for several services only has to leak from the least careful one.')
            ->end();

        $keys = $consumer->arrayNode('keys');
        $keys->info('Names from the `keys` section. Verification tries the key the token names, or the one bound to its algorithm. Optional only when "remote_jwks" is given; with both, these are tried first and the network is never touched for a key already here.');
        $keys->scalarPrototype()->cannotBeEmpty()->end();
        self::rejectMaps($keys, 'consumers.*.keys');

        self::declareOptionalName(
            $consumer,
            'remote_jwks',
            'Name from the `remote_jwks` section: an issuer\'s published key set, fetched and cached rather than configured. Keys the issuer rotates to are picked up without a deploy.',
            'partner_idp',
        );

        $algorithms = $consumer->arrayNode('allowed_algorithms');
        $algorithms->info('JOSE `alg` values accepted. Anything else is refused before a signature is checked.');
        $algorithms->enumPrototype()->values(SigningAlgorithms::names())->end();
        $algorithms->isRequired();
        $algorithms->requiresAtLeastOneElement();
        self::rejectMaps($algorithms, 'consumers.*.allowed_algorithms');

        $consumer->scalarNode('realm')
            ->defaultNull()
            ->cannotBeEmpty()
            ->info('Protection space named in the `WWW-Authenticate` header of this consumer\'s entry point and scope denials (RFC 6750 §3). Null uses the consumer\'s name. Symfony has its own `access_token.realm` for the header it sends itself; keep the two equal. A literal, not an env reference: the value is validated, which is what stops a quote or a newline from costing the header, and Symfony refuses to validate a placeholder.')
            ->example('api')
            ->validate()
                // A quote would close the quoted-string it is interpolated
                // into and let the rest read as further auth-params; a control
                // character is not allowed in one at all (RFC 9110 §5.6.4), and
                // a newline costs the whole header — PHP refuses to emit a
                // header value carrying one, so the 401 goes out with nothing
                // saying how to authenticate. Escaped or stripped on the way
                // out as well, but a realm nobody can read is a configuration
                // mistake worth naming here.
                ->ifTrue(static fn(mixed $value): bool => is_string($value) && (false !== strpbrk($value, "\"\\") || 1 === preg_match(Challenge::CONTROL, $value)))
                ->thenInvalid('A realm cannot contain a quote, a backslash or a control character: it is interpolated into a quoted-string in WWW-Authenticate (RFC 9110 §5.6.4). Got %s')
            ->end()
            ->end();

        $consumer->integerNode('leeway')
            ->defaultValue(0)
            ->min(0)
            ->max(ValidatorBuilder::LEEWAY_CEILING_SECONDS)
            ->info('Clock-skew tolerance in seconds for exp/nbf/iat. The ceiling is the library\'s.')
            ->end();

        self::declareOptionalName(
            $consumer,
            'token_type',
            'The `typ` this consumer expects, for a token whose posture is this application\'s rather than a standard. Naming one verifies the token as a plain JWT with the rules below instead of through the RFC 9068 access-token profile: same keys, algorithms, issuer, audience, leeway and clock, and none of the profile\'s own required claims. Omit it — the default — for the RFC 9068 posture. RFC 7515 §4.1.9 puts the bare form on the wire, so give it without the "application/" prefix.',
            'vnd.acme.session+jwt',
        );

        $required = $consumer->arrayNode('required_claims');
        $required->info('Claims a token must carry, for a consumer that names a `token_type`. Only the presence is checked; what a value means is the application\'s. Left out, it is `["exp"]`: the library checks `exp`, `nbf` and `iat` where a token carries them and nowhere else, so a posture requiring none of them would accept a credential that never stops being valid. A list of your own replaces that — and one omitting `exp` needs `max_token_age` to bound the token instead.');
        $required->scalarPrototype()->cannotBeEmpty()->end();
        $required->defaultValue([]);
        $required->example(['exp', 'sub', 'session_id']);
        self::rejectMaps($required, 'consumers.*.required_claims');

        $consumer->integerNode('max_token_age')
            ->defaultNull()
            ->min(1)
            ->info('Refuse a token older than this many seconds, counted from `iat`, however long its `exp` says it lives. A ceiling of your own on an issuer\'s generosity: a leaked token stops working when this runs out rather than when they decided it should. Off unless set, and `leeway` widens it as it widens every other dated check.')
            ->example('300')
            ->end();

        $denylist = $consumer->arrayNode('denylist')
            ->addDefaultsIfNotSet()
            ->info('Where this consumer asks whether a token has been withdrawn since it was issued. Configured, it costs a lookup per request; unconfigured, nothing is asked and nothing is registered.')
            ->children();

        self::declareOptionalName(
            $denylist,
            'service',
            'Service id implementing TokenDenylistInterface. For a store of your own — the shipped one is a cache, and a cache flush forgets every revocation.',
            'app.token_denylist',
        );

        self::declareOptionalName(
            $denylist,
            'cache_pool',
            'Service id of a PSR-6 cache pool, wrapped for the PSR-16 interface the shipped denylist takes. `cache.app` is a pool.',
            'cache.app',
        );

        self::declareOptionalName(
            $denylist,
            'cache',
            'Service id of a PSR-16 cache, used as it is.',
            'app.simple_cache',
        );

        $denylist->scalarNode('prefix')
            ->defaultValue(self::DEFAULT_DENYLIST_PREFIX)
            ->cannotBeEmpty()
            ->info('Prefix for the cache keys, so revocations do not collide with the rest of the pool. The rest of the key is a hash of the `jti`. PSR-16 §6 reserves {}()/\@: in keys, so those are refused here rather than by the store on every request.')
            ->validate()
                ->ifTrue(static fn(mixed $value): bool => is_string($value) && strlen($value) > 32)
                ->thenInvalid('A denylist prefix over 32 characters can push the key past the 64 PSR-16 guarantees, once the hash of the jti is appended. Got %s')
            ->end()
            ->validate()
                // strpbrk over the reserved set rather than a character class:
                // the backslash in one is a question about two escaping layers,
                // and the pattern that reads as covering it does not.
                ->ifTrue(static fn(mixed $value): bool => is_string($value) && false !== strpbrk($value, '{}()/\\@:'))
                ->thenInvalid('A denylist prefix cannot contain {}()/\@:, which PSR-16 §6 reserves and Symfony\'s cache refuses. A store rejects such a key on every request that checks one, which is a 500 rather than a configuration error. Got %s')
            ->end()
            ->end();

        $user = $consumer->arrayNode('user')
            ->addDefaultsIfNotSet()
            ->children();

        $user->enumNode('mode')
            ->values(['provider', 'claims', 'custom'])
            ->defaultValue('provider')
            ->info('Where the user comes from. "provider" asks the firewall\'s user provider, which is right when a store is the authority. "claims" builds the user from the token, which is right when the issuer is — a resource server verifying a third party\'s tokens usually has nothing to look up. "custom" hands the claims to a service of yours.')
            ->end();

        $user->scalarNode('identity_claim')
            ->defaultValue('sub')
            ->cannotBeEmpty()
            ->info('Claim whose value identifies the user. In "provider" mode it is what the user provider is asked for; mode "custom" ignores it, because the factory names the user it builds.')
            ->end();

        self::declareOptionalName(
            $user,
            'factory',
            'Service id implementing JwtUserFactoryInterface. Required by mode "custom", and refused by the others, which have their own answer.',
            'app.jwt_user_factory',
        );

        $roles = $user->arrayNode('roles')
            ->addDefaultsIfNotSet()
            ->info('How the token\'s claims become roles. Only mode "claims" reads this: a user provider brings its own roles, and a custom factory decides for itself.')
            ->children();

        self::declareOptionalName(
            $roles,
            'claim',
            'Claim carrying what the token grants — "scope" (RFC 6749 §3.3), "roles", "groups" or whatever your issuer sends. A list or a delimited string; both are read.',
            'scope',
        );

        $roles->scalarNode('separator')
            ->defaultValue(' ')
            ->info('Delimiter, when the claim is a string. A space is what `scope` uses. Null treats a string claim as one whole value.')
            ->validate()
                ->ifTrue(static fn(mixed $value): bool => '' === $value)
                ->thenInvalid('A roles separator cannot be the empty string: splitting on nothing has no meaning. Use null to take the claim whole.')
            ->end()
            ->end();

        $roles->scalarNode('prefix')
            ->defaultValue('ROLE_')
            ->info('Prepended to each value, because Symfony\'s access rules speak in ROLE_*. Set it to an empty string if your issuer already sends them prefixed.')
            ->end();

        $defaults = $roles->arrayNode('defaults');
        $defaults->info('Roles every verified token gets, whatever it claims. Empty unless set: a baseline like ROLE_USER is granted only if you ask for it, and nothing invents one.');
        $defaults->scalarPrototype()->cannotBeEmpty()->end();
        $defaults->defaultValue([]);
        self::rejectMaps($defaults, 'consumers.*.user.roles.defaults');
    }

    /**
     * Key sources carry no default: an optional scalar without one is simply
     * absent from the normalised configuration, which {@see KeyEntries::of()}
     * fills in. A null default plus a hand-written emptiness check would read
     * more directly, but a `validate()` closure also runs against the sample
     * values Symfony substitutes for an `%env()%` reference — so it would
     * reject every environment-backed secret. `cannotBeEmpty()` knows about
     * placeholders and does not.
     */
    private static function declareKeySource(NodeBuilder $key, string $name, string $info, string $example): void
    {
        $key->scalarNode($name)
            ->cannotBeEmpty()
            ->info($info)
            ->example($example)
            ->end();
    }

    /**
     * A list-shaped node must not be given a YAML map. Symfony's prototyped
     * array nodes accept arbitrary keys, and the library refuses an associative
     * array — but it refuses it inside a lazily built service, which makes a
     * configuration mistake arrive as a 500 on the first request, phrased as a
     * problem with the token.
     */
    private static function rejectMaps(ArrayNodeDefinition $node, string $name): void
    {
        $node->validate()
            ->ifTrue(static fn(mixed $value): bool => is_array($value) && !array_is_list($value))
            ->thenInvalid(sprintf('medzuch_jwt.%s must be a sequence, not a map. Got %%s', $name))
            ->end();
    }
}
