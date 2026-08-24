<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security\Verification;

use DateInterval;
use Medzuch\Jwt\Algorithm\SigningAlgorithm;
use Medzuch\Jwt\Jwt\MediaType;
use Medzuch\Jwt\Jwt\Validator;
use Medzuch\Jwt\Jwt\ValidatorBuilder;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\KeyResolver;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;

/**
 * Builds the `Validator` behind a consumer that names its own `typ`.
 *
 * A class of its own because Symfony can only call a public method, and the
 * one place a public method must not be is {@see \Medzuch\JwtBundle\MedzuchJwtBundle}:
 * that class is in the backward-compatibility table as something you register
 * in `bundles.php` and never call, and the suite reads `@internal` on classes
 * rather than on methods — so a factory living there would be promised by the
 * policy and disclaimed only by a docblock nothing checks.
 *
 * A factory rather than a chain of `inline_service()` calls because the builder
 * is immutable and conditional in two places, which reads as PHP and does not
 * read as a service definition.
 *
 * @internal
 */
final class CustomValidatorFactory
{
    /**
     * @param list<string>                $audience
     * @param non-empty-list<SigningAlgorithm> $algorithms
     * @param non-empty-list<string>      $requiredClaims
     */
    public static function forTokenType(
        string $tokenType,
        string $issuer,
        array $audience,
        JwkSet|KeyResolver $keys,
        array $algorithms,
        array $requiredClaims,
        ClockInterface $clock,
        ?LoggerInterface $logger,
        ?DateInterval $leeway,
    ): Validator {
        $builder = ValidatorBuilder::create()
            ->expectAlgorithms($algorithms)
            ->withKeys($keys)
            ->expectIssuer($issuer)
            ->expectAudience($audience)
            ->expectType(MediaType::custom($tokenType))
            ->requireClaims($requiredClaims)
            ->withClock($clock);

        if (null !== $leeway) {
            $builder = $builder->withLeeway($leeway);
        }

        if (null !== $logger) {
            $builder = $builder->withLogger($logger);
        }

        return $builder->build();
    }
}
