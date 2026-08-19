<?php

declare(strict_types=1);

use PhpCsFixer\Config;
use PhpCsFixer\Finder;
use PhpCsFixer\Runner\Parallel\ParallelConfigFactory;

$finder = Finder::create()
    ->in([__DIR__ . '/src', __DIR__ . '/tests', __DIR__ . '/config'])
    ->name('*.php')
    ->ignoreDotFiles(true)
    ->ignoreVCS(true);

return (new Config())
    ->setParallelConfig(ParallelConfigFactory::detect())
    ->setRiskyAllowed(true)
    ->setFinder($finder)
    ->setCacheFile(__DIR__ . '/var/php-cs-fixer.cache')
    ->setRules([
        // Same baseline as medzuch/jwt-php: one style across both repositories,
        // so moving between them costs nothing.
        '@PER-CS' => true,
        '@PER-CS:risky' => true,
        '@PHP83Migration' => true,
        '@PHP82Migration:risky' => true,
        '@PHPUnit100Migration:risky' => true,

        'declare_strict_types' => true,
        'strict_param' => true,
        'strict_comparison' => true,
        'final_class' => true,
        'final_internal_class' => true,

        'array_syntax' => ['syntax' => 'short'],
        'no_unused_imports' => true,
        'ordered_imports' => [
            'sort_algorithm' => 'alpha',
            'imports_order' => ['class', 'function', 'const'],
        ],
        'trailing_comma_in_multiline' => true,
        'no_extra_blank_lines' => true,
        'blank_line_before_statement' => ['statements' => ['return', 'throw']],
        'concat_space' => ['spacing' => 'one'],
    ]);
