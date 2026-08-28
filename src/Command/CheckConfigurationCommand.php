<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Command;

use Closure;
use Medzuch\Jwt\Exception\KeyNotFoundException;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\KeyResolver;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Contracts\Service\ServiceProviderInterface;
use Throwable;

/**
 * Builds everything the container left for later, and says what broke.
 *
 * README "From the console" carries what it is for, its exit statuses, and why
 * `ok` means built and not working. Two things about the remote probe are here
 * because they are nowhere else.
 *
 * It does not always reach the endpoint. The resolver reads its cache first, so
 * a warm entry with the refresh window closed answers "reachable" without a
 * request leaving the host — cache-reachable rather than issuer-reachable.
 *
 * And it is the one command here with a side effect: a probe that does reach
 * the endpoint records the attempt, so the issuer's refresh-on-miss window
 * closes for as long as `min_refresh` says. That is the same trade every token
 * bearing an unknown `kid` already makes, and at deploy time it costs nothing
 * worth counting.
 *
 * A set configured by `discovery` is two hops, and the probe covers both: the
 * metadata document has to answer and name its issuer before there is a
 * `jwks_uri` to fetch at all.
 *
 * @internal
 */
#[AsCommand(
    name: 'jwt:config:check',
    description: 'Build every configured key, consumer, issuer and verifier, reach every remote key set, and report what fails',
)]
final class CheckConfigurationCommand extends Command
{
    /** Private JWK members, none of which belongs in a document served to the public. */
    private const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

    /**
     * @param ServiceProviderInterface<object>             $services  what the container builds lazily, keyed by what to call it in the report
     * @param ServiceProviderInterface<KeyResolver>        $remote    key sets that live behind somebody else's HTTP endpoint
     * @param (Closure(): JwkSet)|null                     $published the set the JWKS endpoint serves, or null where nothing is published.
     *                                                                A closure, not the set: injected as a service it would be built when
     *                                                                this command is instantiated, so a published key whose file is
     *                                                                missing — the very case this command exists for — would throw before
     *                                                                the first row was printed, taking every other check with it
     */
    public function __construct(
        private readonly ServiceProviderInterface $services,
        private readonly ServiceProviderInterface $remote,
        private readonly ?Closure $published = null,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption('skip-remote', null, InputOption::VALUE_NONE, 'Do not fetch remote key sets, for a gate that runs without a network')
            ->setHelp(<<<'HELP'
                Builds everything medzuch_jwt configures and reports what fails.

                  <info>%command.full_name%</info>
                  <info>%command.full_name% --skip-remote</info>

                The container refuses the mistakes it can see when it is built. This is for
                the ones it cannot: a key file that was not deployed, an env variable that
                arrived empty, a secret shorter than its algorithm allows, an issuer whose
                JWK Set cannot be reached from here.

                Exit status is 0 when everything answered, 1 when anything did not, and 2
                when this application configures nothing to check — a gate should not go
                green because a package file never arrived.
                HELP)
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $rows = [];

        foreach (array_keys($this->services->getProvidedServices()) as $label) {
            $rows[] = $this->build((string) $label);
        }

        $rows = [...$rows, ...$this->publishedSet()];

        if (true === $input->getOption('skip-remote')) {
            foreach (array_keys($this->remote->getProvidedServices()) as $name) {
                $rows[] = [sprintf('remote JWK Set "%s"', $name), 'skipped', 'not fetched (--skip-remote)'];
            }
        } else {
            foreach (array_keys($this->remote->getProvidedServices()) as $name) {
                $rows[] = $this->reach((string) $name);
            }
        }

        if ([] === $rows) {
            $io->error('This application configures nothing for this bundle to check.');

            // Not SUCCESS: `jwt:config:check && deploy` would go green having
            // checked nothing, which is what a package file that failed to
            // deploy looks like. Not FAILURE either — nothing failed. The same
            // answer `jwt:token:inspect` gives when it is asked to verify
            // against no consumer.
            return Command::INVALID;
        }

        $io->table(['What', 'Status', 'Detail'], $rows);

        $failed = array_filter($rows, static fn(array $row): bool => 'FAIL' === $row[1]);

        if ([] === $failed) {
            $io->success(sprintf('%d checks, nothing to report.', count($rows)));

            return Command::SUCCESS;
        }

        $io->error(sprintf('%d of %d checks failed.', count($failed), count($rows)));

        return Command::FAILURE;
    }

    /**
     * @return array{string, string, string}
     */
    private function build(string $label): array
    {
        try {
            $this->services->get($label);

            return [$label, 'ok', ''];
        } catch (Throwable $failure) {
            // Throwable rather than the library's exceptions: what this asks is
            // "does it come back", and a TypeError from a factory argument is
            // as much of an answer as an InvalidKeyException.
            return [$label, 'FAIL', $failure->getMessage()];
        }
    }

    /**
     * The document the JWKS endpoint would serve, read for the one thing that
     * must never be in it. The container already refuses a symmetric key here;
     * this is the same question asked of the material rather than of the
     * configuration, which is the only way a mistake in the library or in a
     * hand-written JWK would show.
     *
     * @return list<array{string, string, string}>
     */
    private function publishedSet(): array
    {
        if (null === $this->published) {
            return [];
        }

        try {
            $document = ($this->published)()->toArray();
        } catch (Throwable $failure) {
            return [['published JWK Set', 'FAIL', $failure->getMessage()]];
        }

        $keys = $document['keys'] ?? [];
        $keys = is_array($keys) ? $keys : [];

        foreach ($keys as $jwk) {
            $private = is_array($jwk) ? array_intersect(array_keys($jwk), self::PRIVATE_MEMBERS) : [];

            if ([] !== $private) {
                return [['published JWK Set', 'FAIL', sprintf(
                    'a key carries %s, which is private material this document would hand to anyone who asks',
                    '"' . implode('", "', $private) . '"',
                )]];
            }
        }

        return [['published JWK Set', 'ok', sprintf('%d public key(s)', count($keys))]];
    }

    /**
     * @return array{string, string, string}
     */
    private function reach(string $name): array
    {
        $label = sprintf('remote JWK Set "%s"', $name);

        try {
            // A `kid` nobody publishes, so the answer is about the endpoint
            // rather than about any one key: a miss means the document was
            // fetched, parsed, and is a JWK Set — which is the whole question.
            // The `kid` alone, because the resolver selects on it and never
            // reaches the `alg` branch — an `alg` here would read as if the
            // probe depended on one being accepted.
            $this->remote->get($name)->resolve(['kid' => 'jwt-config-check']);

            return [$label, 'ok', 'reachable'];
        } catch (KeyNotFoundException) {
            return [$label, 'ok', 'reachable'];
        } catch (Throwable $failure) {
            return [$label, 'FAIL', $failure->getMessage()];
        }
    }
}
