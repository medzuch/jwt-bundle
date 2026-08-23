<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\DataCollector;

use Medzuch\JwtBundle\Security\RejectionReason;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\DataCollector\DataCollector;
use Throwable;

/**
 * What the tokens in this request turned out to be.
 *
 * The question a profiler panel exists to answer is "why did that 401 happen",
 * and the answer is deliberately absent from the response: RFC 6750 gives a
 * caller `invalid_token` and nothing else. Here, where nobody but the developer
 * is looking, it is the whole point — the reason, the consumer that decided it,
 * the algorithm and key id the token named, and how long the verifying took.
 *
 * **The token itself is never collected.** Profiler data outlives the request:
 * it is written to disk and served back by a URL. A bearer token in there is a
 * credential in a file, and one that a screenshot in a bug report would carry
 * out of the building. Its `jti` names it, and the claims say what it said.
 */
final class JwtDataCollector extends DataCollector
{
    public function collect(Request $request, Response $response, ?Throwable $exception = null): void
    {
        // Nothing to do: the decorated handlers filled this in while the
        // request ran, which is the only time the verdicts exist. A collector
        // asking afterwards would be asking a firewall that has finished.
        $this->data['tokens'] ??= [];
    }

    /**
     * @param array<string, mixed> $claims
     *
     * @internal to {@see \Medzuch\JwtBundle\Security\TraceableAccessTokenHandler}; an application reads this collector rather than writing to it
     */
    public function accepted(string $consumer, string $identity, array $claims, ?string $algorithm, ?string $keyId, float $milliseconds): void
    {
        $this->data['tokens'][] = [
            'consumer' => $consumer,
            'verdict' => 'accepted',
            'reason' => null,
            'detail' => null,
            'identity' => $identity,
            'alg' => $algorithm,
            'kid' => $keyId,
            'duration' => $milliseconds,
            'claims' => $claims,
        ];
    }

    /**
     * @param array<string, mixed> $claims
     *
     * @internal to {@see \Medzuch\JwtBundle\Security\TraceableAccessTokenHandler}; an application reads this collector rather than writing to it
     */
    public function refused(string $consumer, ?RejectionReason $reason, string $detail, ?string $algorithm, ?string $keyId, float $milliseconds, array $claims): void
    {
        $this->data['tokens'][] = [
            'consumer' => $consumer,
            'verdict' => 'refused',
            'reason' => $reason?->value,
            'detail' => $detail,
            'identity' => null,
            'alg' => $algorithm,
            'kid' => $keyId,
            'duration' => $milliseconds,
            'claims' => $claims,
        ];
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function tokens(): array
    {
        $tokens = $this->data['tokens'] ?? [];

        if (!is_array($tokens)) {
            return [];
        }

        // Rebuilt rather than cast: what comes back from the profiler's storage
        // is whatever was serialised, and a panel is not the place to discover
        // that it was something else.
        $rows = [];

        foreach ($tokens as $token) {
            if (is_array($token)) {
                /** @var array<string, mixed> $token */
                $rows[] = $token;
            }
        }

        return $rows;
    }

    public function refusals(): int
    {
        return count(array_filter($this->tokens(), static fn(array $token): bool => 'refused' === ($token['verdict'] ?? null)));
    }

    /**
     * Milliseconds spent verifying, which is the number worth watching: a
     * consumer with a remote key set can spend a round trip here, and the panel
     * is where that shows up as this request's problem rather than as a slow
     * afternoon.
     */
    public function duration(): float
    {
        return array_sum(array_map(
            static fn(array $token): float => is_numeric($token['duration'] ?? null) ? (float) $token['duration'] : 0.0,
            $this->tokens(),
        ));
    }

    public function reset(): void
    {
        $this->data = ['tokens' => []];
    }

    public function getName(): string
    {
        return 'medzuch_jwt';
    }
}
