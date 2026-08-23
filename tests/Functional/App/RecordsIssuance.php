<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use Medzuch\JwtBundle\Event\JwtIssuedEvent;
use Medzuch\JwtBundle\Event\JwtIssuingEvent;

/**
 * A listener on both ends of issuance: it adjusts the claims a test asks it to,
 * and keeps the audit event it was handed afterwards.
 */
final class RecordsIssuance
{
    /**
     * Claims this listener writes when the next token is minted.
     *
     * @var array<string, mixed>
     */
    public array $adjust = [];

    /**
     * Claims this listener deletes when the next token is minted.
     *
     * @var list<string>
     */
    public array $remove = [];

    /** @var array<string, mixed>|null */
    public ?array $sawIssuing = null;

    public ?JwtIssuedEvent $issued = null;

    public function onIssuing(JwtIssuingEvent $event): void
    {
        $this->sawIssuing = $event->claims();

        foreach ($this->adjust as $name => $value) {
            $event->setClaim($name, $value);
        }

        foreach ($this->remove as $name) {
            $event->removeClaim($name);
        }
    }

    public function onIssued(JwtIssuedEvent $event): void
    {
        $this->issued = $event;
    }
}
