<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security\Verification;

use DateInterval;
use Medzuch\Jwt\Algorithm\SigningAlgorithm;
use Medzuch\Jwt\Diagnostics\LogLevels;
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
 * A factory rather than a chain of `inline_service()` calls: the builder is
 * immutable and conditional in two places, which reads as PHP and does not read
 * as a service definition.
 *
 * Its own class rather than a method on the bundle, because Symfony can only
 * call a public one and `MedzuchJwtBundle` is in the backward-compatibility
 * table — `BackwardCompatibilityTest` reads `@internal` on classes and not on
 * methods, so a factory there would be promised by the policy and disclaimed
 * only by a docblock nothing checks.
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
        ?LogLevels $logLevels,
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
            $builder = $builder->withLogger($logger, $logLevels);
        }

        return $builder->build();
    }
}
