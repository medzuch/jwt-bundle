<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * Reports who the firewall decided the caller is — the only thing an
 * end-to-end test of a token handler actually needs to see.
 */
final class WhoAmIController
{
    public function __construct(private readonly Security $security) {}

    public function __invoke(): JsonResponse
    {
        return new JsonResponse(['user' => $this->security->getUser()?->getUserIdentifier()]);
    }
}
