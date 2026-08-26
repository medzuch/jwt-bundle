<?php

declare(strict_types=1);

/*
 * Rewrites the fenced block in docs/configuration-reference.md from
 * `config:dump-reference medzuch_jwt`, leaving the prose around it alone.
 *
 * Kept out of the test that compares them on purpose: a test able to rewrite
 * its own expectation is a test an environment variable can silence, and the
 * configuration tree is a public API surface. Recording a change is a
 * deliberate command someone runs and a diff someone reads.
 *
 *     make config-reference
 */

use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;

require __DIR__ . '/../vendor/autoload.php';

$reference = __DIR__ . '/../docs/configuration-reference.md';

$document = file_get_contents($reference);

if (false === $document) {
    fwrite(\STDERR, "docs/configuration-reference.md is not readable\n");

    exit(1);
}

$kernel = new TestKernel();
$kernel->boot();

$application = new Application($kernel);
$application->setAutoExit(false);

$tester = new CommandTester($application->find('config:dump-reference'));
$tester->execute(['name' => 'medzuch_jwt', '--no-debug' => true]);

$dumped = rtrim($tester->getDisplay(), "\n");

$rewritten = preg_replace(
    '/```text\n.*?\n```/s',
    "```text\n" . str_replace('$', '\\$', $dumped) . "\n```",
    $document,
    1,
    $count,
);

if (null === $rewritten || 1 !== $count) {
    fwrite(\STDERR, "docs/configuration-reference.md should carry exactly one ```text block\n");

    exit(1);
}

file_put_contents($reference, $rewritten);

printf("docs/configuration-reference.md: %d lines recorded\n", substr_count($dumped, "\n") + 1);
