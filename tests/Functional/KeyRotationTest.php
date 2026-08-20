<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Medzuch\JwtBundle\MedzuchJwtBundle;
use Medzuch\JwtBundle\Security\AccessTokenHandler;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * Rotation is a configuration move, not a feature: an issuer signs with one
 * key while a consumer accepts several, so a new key can start signing while
 * tokens from the old one are still in flight.
 *
 * What makes the overlap work is `kid` — without it the resolver takes the
 * first key bound to the algorithm and never tries the second, which is why
 * the configuration refuses that shape (DEC-5).
 */
#[CoversClass(MedzuchJwtBundle::class)]
final class KeyRotationTest extends KernelTestCase
{
    use GeneratesKeypairs;
    use RestoresExceptionHandler;

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        return new TestKernel(self::configuration());
    }

    #[TestDox('a token signed by the retired key still verifies while both are accepted')]
    public function testTokensFromBothKeysVerifyDuringOverlap(): void
    {
        self::bootKernel();

        foreach (['default', 'previous'] as $issuer) {
            $token = self::issuer($issuer)->issue('user-42');

            self::assertSame(
                'user-42',
                self::handler()->getUserBadgeFrom($token->value)->getUserIdentifier(),
                sprintf('a token signed by the "%s" key should verify during the overlap', $issuer),
            );
        }
    }

    private static function issuer(string $name): AccessTokenIssuer
    {
        $issuer = self::getContainer()->get('medzuch_jwt.issuer.' . $name);
        self::assertInstanceOf(AccessTokenIssuer::class, $issuer);

        return $issuer;
    }

    private static function handler(): AccessTokenHandler
    {
        $handler = self::getContainer()->get('medzuch_jwt.handler.api');
        self::assertInstanceOf(AccessTokenHandler::class, $handler);

        return $handler;
    }

    /**
     * The shape of a rotation half-way through: a new key signing, the previous
     * one still accepted, both published.
     *
     * @return array<string, mixed>
     */
    private static function configuration(): array
    {
        $current = self::keypair('current');
        $previous = self::keypair('previous');

        return [
            'keys' => [
                'current_private' => ['pem_private' => $current['private'], 'algorithm' => 'RS256', 'kid' => '2026-01'],
                'current' => ['pem_public' => $current['public'], 'algorithm' => 'RS256', 'kid' => '2026-01'],
                'previous_private' => ['pem_private' => $previous['private'], 'algorithm' => 'RS256', 'kid' => '2025-07'],
                'previous' => ['pem_public' => $previous['public'], 'algorithm' => 'RS256', 'kid' => '2025-07'],
            ],
            'issuers' => [
                // The application has one issuer; `previous` exists only so a
                // test can mint what a token issued before the rotation looks
                // like, without keeping a token fixture around.
                'default' => self::issuerConfig('current_private'),
                'previous' => self::issuerConfig('previous_private'),
            ],
            'consumers' => [
                'api' => [
                    'issuer' => 'https://issuer.test',
                    'audience' => 'https://api.test',
                    'keys' => ['current', 'previous'],
                    'allowed_algorithms' => ['RS256'],
                ],
            ],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function issuerConfig(string $key): array
    {
        return [
            'issuer' => 'https://issuer.test',
            'key' => $key,
            'client_id' => 'test-client',
            'audience' => 'https://api.test',
        ];
    }

}
