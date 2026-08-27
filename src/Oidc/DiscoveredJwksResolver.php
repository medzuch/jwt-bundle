<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Oidc;

use Medzuch\Jwt\Diagnostics\LogLevels;
use Medzuch\Jwt\Diagnostics\SecurityLog;
use Medzuch\Jwt\Exception\JwksResolutionException;
use Medzuch\Jwt\Key\Key;
use Medzuch\Jwt\Key\KeyResolver;
use Medzuch\Jwt\Key\Resolver\RemoteJwksResolver;
use Medzuch\Jwt\Primitives\Json;
use Psr\Clock\ClockInterface;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;
use Throwable;

/**
 * Resolves verification keys from an issuer identifier rather than a
 * `jwks_uri`, by reading the issuer's discovery document (K7).
 *
 * README "Discovering an issuer's keys" says what an application gets from it.
 * What it costs is one indirection: the endpoint holding the keys is now
 * something the issuer states at runtime, so it is read, checked and cached
 * before {@see RemoteJwksResolver} is handed the result. Two things make that
 * safe to do at all:
 *
 *  - **The issuer identifier is the trust anchor.** OIDC Discovery §4.3 makes
 *    the document's own `issuer` a required, exactly-matching echo of the
 *    identifier it was fetched for. Without that check a discovery document is
 *    a redirect to whatever keys it likes; with it, an endpoint can only ever
 *    speak for the issuer already configured here.
 *  - **Both hops are HTTPS.** The identifier is refused at container build
 *    when it is not, and a `jwks_uri` that comes back plaintext is refused
 *    here — the second is the one an issuer chooses, so configuration cannot
 *    settle it in advance.
 *
 * Failures surface as {@see JwksResolutionException}, which is the same
 * exception a fetch of a configured `jwks_uri` throws. That is what keeps K6
 * true through a discovery outage: a `CompositeResolver` falls through to the
 * locally configured keys rather than failing the request.
 *
 * @internal
 */
final class DiscoveredJwksResolver implements KeyResolver
{
    /**
     * OIDC Discovery §4: the identifier, then this path. RFC 8414 inserts its
     * own suffix before a path component instead, which matters only for an
     * issuer identifier that has a path — and an OpenID Provider publishes
     * both spellings when it has one.
     */
    private const WELL_KNOWN = '/.well-known/openid-configuration';

    private const READ_CHUNK_BYTES = 8192;

    private readonly string $cacheKey;

    private readonly ?SecurityLog $log;

    private ?KeyResolver $delegate = null;

    public function __construct(
        private readonly string $issuer,
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly CacheInterface $cache,
        private readonly ClockInterface $clock,
        private readonly int $cacheTtlSeconds = 300,
        private readonly int $minRefreshSeconds = 60,
        private readonly int $maxBodyBytes = 256 * 1024,
        private readonly ?LoggerInterface $logger = null,
        private readonly ?LogLevels $logLevels = null,
    ) {
        $this->log = null === $logger ? null : SecurityLog::for($logger, $logLevels);

        // PSR-16 forbids {}()/\@: in keys, and the identifier is a URL.
        $this->cacheKey = 'oidc_discovery_' . hash('sha256', $this->issuerIdentifier());
    }

    public function resolve(array $header): Key
    {
        return $this->keys()->resolve($header);
    }

    /**
     * The delegate, built once per request from the discovered endpoint.
     *
     * Memoised on the instance as well as in the cache: the cache round-trip
     * is cheap but not free, and within one request the answer cannot change.
     */
    private function keys(): KeyResolver
    {
        if (null !== $this->delegate) {
            return $this->delegate;
        }

        $jwksUri = $this->jwksUri();

        return $this->delegate = new RemoteJwksResolver(
            $jwksUri,
            $this->httpClient,
            $this->requestFactory,
            $this->cache,
            $this->clock,
            $this->cacheTtlSeconds,
            $this->minRefreshSeconds,
            $this->maxBodyBytes,
            $this->logger,
            $this->logLevels,
        );
    }

    /** @throws JwksResolutionException */
    private function jwksUri(): string
    {
        $cached = $this->cache->get($this->cacheKey);

        if (is_string($cached) && '' !== $cached) {
            $this->log?->keyResolved($cached, 'cache');

            return $cached;
        }

        try {
            $jwksUri = $this->read($this->fetch());
        } catch (JwksResolutionException $e) {
            $this->log?->keyResolutionFailed($e, $this->discoveryUri());

            throw $e;
        }

        $this->cache->set($this->cacheKey, $jwksUri, $this->cacheTtlSeconds);

        return $jwksUri;
    }

    /**
     * The `jwks_uri` this document states, once it has proved it is allowed to
     * state one.
     *
     * @throws JwksResolutionException
     */
    private function read(string $body): string
    {
        try {
            $document = Json::decode($body);
        } catch (Throwable $e) {
            throw new JwksResolutionException(sprintf('Discovery document at "%s" is not JSON: %s', $this->discoveryUri(), $e->getMessage()), previous: $e);
        }

        $stated = $document['issuer'] ?? null;

        if (!is_string($stated) || rtrim($stated, '/') !== $this->issuerIdentifier()) {
            throw new JwksResolutionException(sprintf(
                'Discovery document at "%s" states issuer %s, not "%s" (OIDC Discovery §4.3). A document that may name its own issuer may name anyone\'s keys.',
                $this->discoveryUri(),
                is_string($stated) ? '"' . $stated . '"' : 'nothing',
                $this->issuerIdentifier(),
            ));
        }

        $jwksUri = $document['jwks_uri'] ?? null;

        if (!is_string($jwksUri) || '' === $jwksUri) {
            throw new JwksResolutionException(sprintf('Discovery document at "%s" states no "jwks_uri".', $this->discoveryUri()));
        }

        if (0 !== stripos($jwksUri, 'https://')) {
            throw new JwksResolutionException(sprintf('Discovery document at "%s" states a jwks_uri that is not https: "%s" (RFC 8725 §3.10).', $this->discoveryUri(), $jwksUri));
        }

        return $jwksUri;
    }

    /** @throws JwksResolutionException */
    private function fetch(): string
    {
        $uri = $this->discoveryUri();
        $request = $this->requestFactory->createRequest('GET', $uri);

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new JwksResolutionException(sprintf('Discovery fetch from "%s" failed: %s', $uri, $e->getMessage()), previous: $e);
        }

        $status = $response->getStatusCode();

        if (200 !== $status) {
            throw new JwksResolutionException(sprintf('Discovery endpoint "%s" returned HTTP %d', $uri, $status));
        }

        return $this->readBounded($response->getBody(), $uri);
    }

    /**
     * The same ceiling the JWK Set is read under, applied to the document that
     * points at it: an endpoint that can answer with an endless body is not
     * made safe by what the body was supposed to contain.
     *
     * @throws JwksResolutionException
     */
    private function readBounded(StreamInterface $stream, string $uri): string
    {
        $body = '';

        while (!$stream->eof()) {
            $chunk = $stream->read(self::READ_CHUNK_BYTES);
            $body .= $chunk;

            if (strlen($body) > $this->maxBodyBytes) {
                throw new JwksResolutionException(sprintf('Discovery response from "%s" exceeds the %d-byte limit', $uri, $this->maxBodyBytes));
            }

            if ('' === $chunk) {
                break;
            }
        }

        return $body;
    }

    /**
     * The identifier as OIDC Discovery compares it: one trailing slash is the
     * difference between `https://idp.example.com` and the same issuer written
     * with a slash, and providers are not consistent about which they publish.
     * Comparing both sides stripped keeps that spelling out of the failure.
     */
    private function issuerIdentifier(): string
    {
        return rtrim($this->issuer, '/');
    }

    private function discoveryUri(): string
    {
        return $this->issuerIdentifier() . self::WELL_KNOWN;
    }
}
