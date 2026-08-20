<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use Medzuch\JwtBundle\Oidc\IdTokenVerifier;

/**
 * A controller as an application would write it: the verifier arrives by
 * argument name, which is the registration name. Nothing here calls the
 * container.
 */
final class OidcCallback
{
    public function __construct(public readonly IdTokenVerifier $partner) {}
}
