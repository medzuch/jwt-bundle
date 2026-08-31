<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Symfony\Component\ErrorHandler\ErrorHandler;

/**
 * Undoes the exception handler `FrameworkBundle` installs when it boots in
 * debug mode and never removes, which PHPUnit accounts for and reports as a
 * risky test.
 *
 * Restoring unconditionally would pop PHPUnit's own handler whenever a boot
 * failed before installing one — the configuration tests throw during
 * compilation — so this inspects what is on top first: `set_exception_handler`
 * returns the current handler, and the probe is undone immediately.
 */
trait RestoresExceptionHandler
{
    protected function tearDown(): void
    {
        parent::tearDown();

        $this->restoreExceptionHandler();
    }

    /**
     * The restoration on its own, for a case class that needs a `tearDown()`
     * of its own: a method on the class wins over a trait's silently, and the
     * handler would simply stay up — which the current Symfony does not report
     * and the 6.4 floor does, as sixteen risky tests.
     */
    protected function restoreExceptionHandler(): void
    {
        $current = set_exception_handler(null);
        restore_exception_handler();

        if (is_array($current) && $current[0] instanceof ErrorHandler) {
            restore_exception_handler();
        }
    }
}
