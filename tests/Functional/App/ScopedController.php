<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Security\Http\Attribute\IsGranted;

/**
 * The attribute the scope voter exists for. `access_control` and `#[IsGranted]`
 * reach the voter by different listeners, and only one of them was covered.
 */
final class ScopedController
{
    #[IsGranted('SCOPE_reports.read')]
    public function __invoke(): JsonResponse
    {
        return new JsonResponse(['reports' => []]);
    }
}
