<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use Psr\SimpleCache\CacheException;
use RuntimeException;

/**
 * What {@see ThrowingCache} throws.
 *
 * A PSR-16 adapter reports a store it cannot reach as an exception
 * implementing `CacheException`, so the stand-in does too: the assertion is
 * about which exceptions the authenticator catches, and it is worth making
 * with the shape a real Redis adapter would hand it.
 */
final class CacheIsDown extends RuntimeException implements CacheException {}
