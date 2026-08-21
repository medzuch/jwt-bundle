<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security\Authorization;

use Symfony\Component\ExpressionLanguage\ExpressionFunction;
use Symfony\Component\ExpressionLanguage\ExpressionFunctionProviderInterface;

/**
 * `is_granted_scope('users.write')` in an expression, which is
 * `is_granted('SCOPE_users.write')` with the prefix kept out of the string.
 *
 * Sugar, and openly so: the value is that an expression in `access_control` or
 * an `#[IsGranted]` says *scope* where a scope is meant, instead of a role
 * name that happens to start with four letters that mean something.
 *
 * @internal
 */
final class ScopeExpressionProvider implements ExpressionFunctionProviderInterface
{
    /**
     * @return list<ExpressionFunction>
     */
    public function getFunctions(): array
    {
        return [
            new ExpressionFunction(
                'is_granted_scope',
                static fn(string $scope): string => sprintf('$auth_checker->isGranted("%s" . %s)', ScopeVoter::PREFIX, $scope),
                static fn(array $variables, string $scope): bool => $variables['auth_checker']->isGranted(ScopeVoter::PREFIX . $scope),
            ),
        ];
    }
}
