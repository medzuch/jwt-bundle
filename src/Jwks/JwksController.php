<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Jwks;

use Medzuch\Jwt\Key\JwkSet;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Serves the public keys a relying party needs to verify this issuer's tokens
 * (RFC 7517 §5).
 *
 * The set is built from verification halves only, and the configuration refuses
 * to put a symmetric key in it: publishing an `oct` JWK would hand out the key
 * that signs. That check lives at container build, because the one thing this
 * endpoint must never do is succeed at the wrong moment.
 *
 * The bundle deliberately registers no route. Where a JWKS document lives is
 * the application's decision — under `/.well-known/`, behind a prefix, on a
 * separate host — and a route the bundle owns would either take that choice
 * away or duplicate it.
 */
final class JwksController
{
    public function __construct(
        private readonly JwkSet $keys,
        private readonly int $maxAge,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        $response = new JsonResponse($this->keys->toArray());

        // RFC 7517 §8.5. Caches and clients that know the media type treat the
        // document as a key set rather than as arbitrary JSON.
        $response->headers->set('Content-Type', 'application/jwk-set+json');

        // Public keys are public by definition, and a relying party that cannot
        // cache them refetches on every token it verifies.
        $response->setPublic();
        $response->setMaxAge($this->maxAge);

        // The document is a pure function of the configured keys, so its own
        // content is the validator. This is also what makes a `cache_max_age`
        // of zero mean revalidate rather than refetch: without a validator a
        // client has nothing to ask "still current?" with.
        $response->setEtag(hash('xxh128', (string) $response->getContent()));
        $response->isNotModified($request);

        return $response;
    }
}
