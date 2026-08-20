<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;

/**
 * The identity provider, without a network.
 *
 * A test that fetched a real `jwks_uri` would assert the internet works. This
 * answers what it is told to answer and records what was asked, which is what
 * the caching and fallback behaviour has to be judged on.
 *
 * It is a PSR-17 request factory as well as a PSR-18 client, because that is
 * the shape Symfony's own `psr18.http_client` has and the shape the bundle
 * defaults to.
 */
final class StubHttpClient implements ClientInterface, RequestFactoryInterface
{
    /** @var list<string> */
    public array $requested = [];

    private string $body = '{"keys": []}';

    private int $status = 200;

    private bool $offline = false;

    private readonly Psr17Factory $factory;

    public function __construct()
    {
        $this->factory = new Psr17Factory();
    }

    public function publishes(string $body, int $status = 200): void
    {
        $this->body = $body;
        $this->status = $status;
        $this->offline = false;
    }

    public function goesOffline(): void
    {
        $this->offline = true;
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->requested[] = (string) $request->getUri();

        if ($this->offline) {
            throw new TransportFailure('the identity provider is unreachable');
        }

        return new Response($this->status, ['Content-Type' => 'application/jwk-set+json'], $this->body);
    }

    public function createRequest(string $method, $uri): RequestInterface
    {
        \assert(is_string($uri) || $uri instanceof UriInterface);

        return $this->factory->createRequest($method, $uri);
    }
}
