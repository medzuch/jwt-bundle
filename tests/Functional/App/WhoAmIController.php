<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * Reports who the firewall decided the caller is, and what it decided they
 * may do — the two things an end-to-end test of a token handler needs to see.
 */
final class WhoAmIController
{
    public function __construct(private readonly Security $security) {}

    public function __invoke(): JsonResponse
    {
        $user = $this->security->getUser();

        return new JsonResponse(['user' => $user?->getUserIdentifier(), 'roles' => $user?->getRoles() ?? []]);
    }
}
