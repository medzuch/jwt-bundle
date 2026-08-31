<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security;

use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Jwe\CompactSerializer as JweCompactSerializer;
use Medzuch\Jwt\Jwt\JwtParser;
use Medzuch\JwtBundle\Event\JwtRejectedEvent;
use Psr\Container\ContainerInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use UnexpectedValueException;

/**
 * One firewall in front of several consumers, choosing between them by the
 * issuer the token names (C11).
 *
 * **The issuer it reads is unverified, and that is safe here because routing
 * grants nothing.** A token is parsed only far enough to find `iss`; the
 * consumer that name selects then verifies everything from the beginning,
 * including that `iss` is its own. Claiming to be somebody else therefore buys
 * an attacker the right to be judged by that somebody's consumer, against that
 * somebody's keys — which is the consumer they would have faced had they sent
 * the token to the firewall directly. Nothing is skipped and nothing is
 * softened: this picks a judge, it does not testify.
 *
 * **The allowlist is the configured consumers and nothing else.** An issuer no
 * listed consumer expects is refused as `wrong_issuer` before a key is
 * fetched, and so is a token whose issuer cannot be read at all. There is no
 * default route: a fallback consumer would be the one everything unrecognised
 * ends up at, which is the opposite of what a tenant boundary is for.
 *
 * **An encrypted token routes on the issuer replicated in its outer header**
 * (RFC 7519 §5.3), because a JWE has nothing else to read without a key — and
 * this is the case §5.3 exists for. The consumer it lands on decrypts, and
 * holds the copy to the claim inside; a mismatch is its refusal to make, not
 * this one's. An encrypted token that replicates nothing has no issuer here
 * and is refused, which is why a tenant sending one has to be asked to
 * replicate it.
 *
 * Consumers arrive through a service locator, so a request builds the one
 * consumer it routed to. A dispatcher in front of twenty tenants does not open
 * twenty denylists to answer one token.
 *
 * @internal
 */
final class IssuerDispatchingHandler implements AccessTokenHandlerInterface
{
    /** @var array<string, string> issuer value => consumer name */
    private readonly array $routes;

    /**
     * @param array<string, string> $issuers the `iss` each listed consumer expects, keyed by
     *                                       consumer name. Given this way round because that is
     *                                       the way round the configuration is written, and
     *                                       because two tenants configured with one issuer have
     *                                       to be caught rather than silently collapsed into a
     *                                       single route
     * @param ContainerInterface    $consumers locator of `AccessTokenHandlerInterface`, keyed by
     *                                         consumer name
     */
    public function __construct(
        array $issuers,
        private readonly ContainerInterface $consumers,
        private readonly string $name,
        private readonly ?EventDispatcherInterface $events = null,
    ) {
        $routes = [];

        foreach ($issuers as $consumer => $issuer) {
            // Not a container-build check, because an issuer is routinely an
            // env reference and has no value until here. `jwt:config:check`
            // builds every dispatcher, which is where a deploy finds out.
            if (isset($routes[$issuer])) {
                throw new UnexpectedValueException(sprintf(
                    'Dispatcher "%s" cannot choose between consumers "%s" and "%s": both expect issuer "%s", and the token names one issuer.',
                    $name,
                    $routes[$issuer],
                    $consumer,
                    $issuer,
                ));
            }

            $routes[$issuer] = $consumer;
        }

        $this->routes = $routes;
    }

    public function getUserBadgeFrom(string $accessToken): UserBadge
    {
        $issuer = self::issuerOf($accessToken);

        if (null === $issuer || !isset($this->routes[$issuer])) {
            throw $this->refused();
        }

        $consumer = $this->consumers->get($this->routes[$issuer]);

        if (!$consumer instanceof AccessTokenHandlerInterface) {
            throw new UnexpectedValueException(sprintf('Consumer "%s" behind dispatcher "%s" is not an access-token handler.', $this->routes[$issuer], $this->name));
        }

        return $consumer->getUserBadgeFrom($accessToken);
    }

    /**
     * The issuer a token names, read without verifying anything, or null where
     * there is nothing to read.
     *
     * A signed token carries it as a claim; an encrypted one carries it only if
     * the sender replicated it into the outer header. Tried in that order for
     * the reason {@see TraceableAccessTokenHandler} tries it in that order: a
     * three-segment string is the ordinary case, and asking the JWE serializer
     * about one would only ever be answered with a refusal.
     */
    private static function issuerOf(string $token): ?string
    {
        try {
            return JwtParser::parse($token)->unverifiedClaims->issuer();
        } catch (JwtException) {
        }

        try {
            $header = JweCompactSerializer::deserialize($token)->header;
        } catch (JwtException) {
            return null;
        }

        $issuer = $header['iss'] ?? null;

        return is_string($issuer) ? $issuer : null;
    }

    /**
     * Announced under the dispatcher's own name, because nothing else will
     * announce it: a token that routes nowhere never reaches a consumer, and a
     * refusal no listener hears is one nobody can count.
     *
     * The reason is `wrong_issuer` whether the issuer was unknown or unreadable
     * — both are the same fact about the same question, which is whether this
     * dispatcher has a consumer for this token.
     */
    private function refused(): RejectedTokenException
    {
        // The issuer the token named is not in it: the message reaches a log
        // and an exception page, and neither is a place to echo a string an
        // unauthenticated caller chose. What it was is in the profiler panel,
        // which reads the token itself.
        $failure = new RejectedTokenException(
            RejectionReason::WrongIssuer,
            sprintf('No consumer behind dispatcher "%s" expects this token\'s issuer.', $this->name),
        );

        $this->events?->dispatch(new JwtRejectedEvent($this->name, RejectionReason::WrongIssuer, $failure));

        return $failure;
    }
}
