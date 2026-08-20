<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use Psr\Http\Client\ClientExceptionInterface;
use RuntimeException;

/** What a PSR-18 client throws when it cannot reach the endpoint at all. */
final class TransportFailure extends RuntimeException implements ClientExceptionInterface {}
