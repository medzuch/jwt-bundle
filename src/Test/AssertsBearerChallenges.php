<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Test;

use PHPUnit\Framework\Assert;
use Symfony\Component\HttpFoundation\Response;

/**
 * Assertions about the `WWW-Authenticate` header a refusal carries.
 *
 * The alternative is asserting the whole string, which is what this bundle's
 * own suite did until the realm changed and every case had to be edited. A
 * refusal is a few facts — a challenge was made, this error was named, this
 * scope would have sufficed — and a test should say which of them it is about.
 *
 * The scheme and the parameter names are matched case-insensitively, because
 * RFC 9110 §11.6.1 says both are, and the spacing between parameters is ignored
 * because Symfony's own header and this bundle's differ in it — a test should
 * not fail over which of them answered.
 *
 * One challenge per header is assumed: every `name="value"` after the scheme is
 * read. A response carrying `Bearer …, Basic …` would have both schemes'
 * parameters in one map, and splitting that correctly is a parser rather than a
 * test helper. Symfony emits one challenge; if yours emits two, assert on the
 * header yourself.
 *
 * Used from a PHPUnit test case; it calls PHPUnit's assertions and is useless
 * anywhere else.
 */
trait AssertsBearerChallenges
{
    /**
     * A `WWW-Authenticate: Bearer` with no `error` — RFC 6750 §3 for a request
     * that presented no credentials, where naming an error would describe a
     * failure that did not happen.
     */
    public static function assertBearerChallenge(Response $response, ?string $realm = null): void
    {
        $challenge = self::bearerChallenge($response);

        Assert::assertArrayNotHasKey('error', $challenge, 'a challenge to a request carrying no token should name no error');

        if (null !== $realm) {
            Assert::assertSame($realm, $challenge['realm'] ?? null);
        }
    }

    /**
     * The refusal of a token that was presented and not accepted (RFC 6750
     * §3.1). Symfony's own authenticator writes this one.
     */
    public static function assertInvalidToken(Response $response): void
    {
        $challenge = self::bearerChallenge($response);

        Assert::assertSame('invalid_token', $challenge['error'] ?? null);
    }

    /**
     * A `403` naming the scope that would have sufficed. Pass one to assert it
     * is named, or none to assert only that the refusal was about scope.
     */
    public static function assertInsufficientScope(Response $response, ?string $scope = null): void
    {
        $challenge = self::bearerChallenge($response);

        Assert::assertSame('insufficient_scope', $challenge['error'] ?? null);

        if (null === $scope) {
            return;
        }

        $named = explode(' ', $challenge['scope'] ?? '');

        Assert::assertContains($scope, $named, sprintf('the challenge names "%s", not "%s"', $challenge['scope'] ?? '', $scope));
    }

    /**
     * No challenge at all, which is the right answer to a denial this bundle
     * has nothing to say about: a role, an expression, an attribute that is not
     * a scope.
     */
    public static function assertNoBearerChallenge(Response $response): void
    {
        Assert::assertNull(
            $response->headers->get('WWW-Authenticate'),
            'this refusal should carry no bearer challenge',
        );
    }

    /**
     * @return array<string, string> the challenge's auth-params, unquoted
     */
    private static function bearerChallenge(Response $response): array
    {
        $header = $response->headers->get('WWW-Authenticate');

        Assert::assertIsString($header, 'the response carries no WWW-Authenticate header');
        Assert::assertMatchesRegularExpression('/^Bearer\\b/i', $header, sprintf('not a bearer challenge: %s', $header));

        $parameters = [];

        // Both forms RFC 9110 §11.2 allows for an auth-param value: the quoted
        // string everything here writes, and the bare token another
        // implementation or a gateway might. Names take digits and hyphens
        // because `token` does, even though nothing in RFC 6750 uses them.
        preg_match_all(
            '/([a-z0-9_-]+)=(?:"((?:[^"\\\\]|\\\\.)*)"|([^\\s,]+))/i',
            substr($header, strlen('Bearer')),
            $matches,
            \PREG_SET_ORDER,
        );

        foreach ($matches as $match) {
            $parameters[strtolower($match[1])] = '' !== ($match[2] ?? '') ? stripslashes($match[2]) : ($match[3] ?? $match[2] ?? '');
        }

        return $parameters;
    }
}
