<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use Medzuch\JwtBundle\Event\JwtRejectedEvent;
use Medzuch\JwtBundle\Event\JwtVerifiedEvent;

/**
 * Keeps what a consumer said about the tokens it was shown.
 */
final class RecordsVerification
{
    /** @var list<JwtVerifiedEvent> */
    public array $verified = [];

    /** @var list<JwtRejectedEvent> */
    public array $rejected = [];

    public function onVerified(JwtVerifiedEvent $event): void
    {
        $this->verified[] = $event;
    }

    public function onRejected(JwtRejectedEvent $event): void
    {
        $this->rejected[] = $event;
    }
}
