<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Oidc;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Serves this application's own authorization-server metadata (K8, RFC 8414):
 * the document a relying party reads to find out who this issuer is and where
 * its keys live.
 *
 * The other side of {@see DiscoveredJwksResolver}, which reads such a document
 * from somebody else. What that class refuses is what this one has to get
 * right: the `issuer` here is the identifier the document is fetched for, and
 * `jwks_uri` is https, or a careful reader throws the document away.
 *
 * **This bundle is not an authorization server** (§8 non-goal 3), and the
 * document says so by what it contains. Only two members are filled in from
 * configuration this bundle owns — `issuer` and `jwks_uri` — because they are
 * the only two it knows. Everything else an OAuth or OIDC deployment publishes
 * describes endpoints and grants that live in the application: those come from
 * `metadata.extra` verbatim, and the configuration refuses a document without
 * the `response_types_supported` RFC 8414 §2 requires rather than serving an
 * incomplete one with a 200.
 *
 * The bundle registers no route: DEC-6 has why that is the application's
 * decision, and it is also what lets one controller answer at either well-known
 * path — RFC 8414's `oauth-authorization-server` or OIDC Discovery's
 * `openid-configuration` — since the two differ in what they carry rather than
 * in how they are served.
 *
 * @internal
 */
final class MetadataController
{
    /**
     * @param array<string, mixed> $document the whole document, assembled at container
     *                                       build: nothing here varies per request, and a document
     *                                       computed per call would be a different answer to the same
     *                                       question every time a cache asked
     */
    public function __construct(
        private readonly array $document,
        private readonly int $maxAge,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        $response = new JsonResponse($this->document);

        // Public because the document is: it names endpoints and identifiers,
        // and a relying party that cannot cache it refetches before every key
        // fetch it was supposed to save.
        $response->setPublic();
        $response->setMaxAge($this->maxAge);

        // The same reasoning the JWK Set is served under: the document is a
        // pure function of configuration, so its own content is the validator,
        // and a `cache_max_age` of zero means revalidate rather than refetch.
        $response->setEtag(hash('xxh128', (string) $response->getContent()));
        $response->isNotModified($request);

        return $response;
    }
}
