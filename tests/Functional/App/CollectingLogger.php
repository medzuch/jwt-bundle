<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use Psr\Log\AbstractLogger;

/**
 * Keeps what was logged, so a test can assert that configuring `logger`
 * actually reaches the library's own security log.
 */
final class CollectingLogger extends AbstractLogger
{
    /** @var list<array{level: string, message: string}> */
    public array $records = [];

    public function log(mixed $level, string|\Stringable $message, array $context = []): void
    {
        $this->records[] = [
            'level' => is_scalar($level) ? (string) $level : get_debug_type($level),
            'message' => (string) $message,
        ];
    }
}
