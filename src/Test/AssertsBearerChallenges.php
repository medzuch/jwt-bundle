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
 * Header parameters are matched case-insensitively in the scheme and by name,
 * because RFC 9110 §11.6.1 says the scheme is case-insensitive and Symfony's
 * own header differs from this bundle's in spacing.
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
        Assert::assertStringStartsWith('Bearer', $header, sprintf('not a bearer challenge: %s', $header));

        $parameters = [];

        // Deliberately forgiving about spacing: this bundle writes ", " between
        // parameters and Symfony writes ",", and a test asserting a fact about
        // the challenge should not fail over which of them answered.
        preg_match_all('/([a-z_]+)="((?:[^"\\\\]|\\\\.)*)"/i', substr($header, strlen('Bearer')), $matches, \PREG_SET_ORDER);

        foreach ($matches as $match) {
            $parameters[strtolower($match[1])] = stripslashes($match[2]);
        }

        return $parameters;
    }
}
