<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Command;

use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Medzuch\JwtBundle\Issuer\ReservedClaims;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Contracts\Service\ServiceProviderInterface;

/**
 * Mints a token from the command line, through the configured issuer.
 *
 * Through it, not beside it: the command asks the same `AccessTokenIssuer` a
 * controller would, so a token it prints is signed with the configured key,
 * carries the configured audience and client id, and passes through the
 * application's claim providers and issuing listeners. A CLI that assembled its
 * own token would be a second implementation, and the first thing it would be
 * used for is proving the first one wrong.
 *
 * `--raw` prints the token and nothing else, which is what a shell wants:
 *
 *     TOKEN=$(bin/console jwt:token:create alice --raw)
 *
 * @internal
 */
#[AsCommand(
    name: 'jwt:token:create',
    description: 'Mint an access token through a configured issuer',
)]
final class CreateTokenCommand extends Command
{
    /**
     * @param ServiceProviderInterface<AccessTokenIssuer> $issuers
     */
    public function __construct(private readonly ServiceProviderInterface $issuers)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addArgument('subject', InputArgument::REQUIRED, 'Who the token is about — the "sub" claim')
            ->addOption('issuer', null, InputOption::VALUE_REQUIRED, 'Name of the configured issuer to mint with. One configured issuer is used without asking; among several, "default" is the tiebreak')
            ->addOption('scope', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Scope to grant. Repeat for several')
            ->addOption('audience', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Narrow "aud" to these for this token. Repeat for several')
            ->addOption('ttl', null, InputOption::VALUE_REQUIRED, 'Lifetime in seconds, overriding the issuer\'s')
            ->addOption('claim', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Extra claim as name=value. Repeat for several. Values are strings')
            ->addOption('raw', null, InputOption::VALUE_NONE, 'Print the token alone, for a shell to capture')
            ->setHelp(<<<'HELP'
                Mints one access token through a configured issuer.

                  <info>%command.full_name% alice --scope reports.read --scope reports.write</info>
                  <info>%command.full_name% svc-billing --ttl 60 --audience https://reports.example.com</info>
                  <info>TOKEN=$(bin/console %command.name% alice --raw)</info>

                Every option after the subject narrows what configuration already decided,
                exactly as the arguments of AccessTokenIssuer::issue() do — because that is
                what this command calls. Your claim providers and JwtIssuingEvent listeners
                run here too, so what is printed is what your application would have minted.

                --issuer can be left out where one issuer is configured. The registered
                claims are set from the arguments above and cannot be given with --claim;
                "client_id" and "scope" can, and they replace the configured client id and
                --scope respectively, which is the issuer's own rule for a caller's claims.

                What comes out is a working credential for as long as it lives. It is on
                your screen and in your shell history; --raw keeps it out of a log file at
                least.
                HELP)
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $configured = array_keys($this->issuers->getProvidedServices());

        if (self::isBlank($input->getOption('issuer'))) {
            $io->error(sprintf('--issuer names one of %s, and is not empty.', self::listOf($configured)));

            return Command::INVALID;
        }

        $name = self::string($input, 'issuer') ?? self::theIssuer($configured);

        if (null === $name) {
            $io->error(sprintf(
                'Several issuers are configured and none of them is "default", so there is nothing to assume. Name one with --issuer: %s.',
                self::listOf($configured),
            ));

            return Command::INVALID;
        }

        if (!$this->issuers->has($name)) {
            $io->error(sprintf('No issuer named "%s" is configured. Configured: %s.', $name, self::listOf($configured)));

            return Command::INVALID;
        }

        $subject = self::string($input, 'subject');

        if (null === $subject) {
            $io->error('The subject cannot be empty: it is what the token is about, and a consumer refuses a token that names nobody.');

            return Command::INVALID;
        }

        $claims = self::claims($input);

        if (null === $claims) {
            $io->error('Each --claim is name=value, and the name cannot be empty.');

            return Command::INVALID;
        }

        $registered = array_values(array_intersect(array_keys($claims), ReservedClaims::REGISTERED));

        if ([] !== $registered) {
            // Refused here rather than left to the library, which refuses the
            // same names inside a builder — from where the answer is a stack
            // trace reading like a bug in this bundle, for what is a typo in an
            // argument. Every other bad input to this command is refused before
            // anything is signed, and a claim name is no different.
            $io->error(sprintf(
                'The claim %s is set from the token itself and cannot be given with --claim. Set from arguments or configuration: %s.',
                '"' . implode('", "', $registered) . '"',
                '"' . implode('", "', ReservedClaims::REGISTERED) . '"',
            ));

            return Command::INVALID;
        }

        $ttl = self::ttl($input);

        if (false === $ttl) {
            $io->error('--ttl is a whole number of seconds, greater than zero.');

            return Command::INVALID;
        }

        $scopes = self::strings($input, 'scope');
        $audience = self::strings($input, 'audience');

        $issuer = $this->issuers->get($name);

        if (!$issuer instanceof AccessTokenIssuer) {
            $io->error(sprintf('The service behind issuer "%s" is not an AccessTokenIssuer.', $name));

            return Command::FAILURE;
        }

        $token = $issuer->issue(
            $subject,
            $scopes,
            $claims,
            $ttl,
            [] === $audience ? null : $audience,
        );

        if (true === $input->getOption('raw')) {
            // No SymfonyStyle: it would decorate, wrap and pad a value a shell
            // is about to capture.
            $output->writeln($token->value, OutputInterface::OUTPUT_RAW);

            return Command::SUCCESS;
        }

        $io->section('Token');
        $io->writeln($token->value);

        $io->definitionList(
            ['Issuer' => $name],
            ['Subject' => $subject],
            ['Scopes' => [] === $scopes ? '(none)' : implode(' ', $scopes)],
            ['Audience' => [] === $audience ? '(the issuer\'s)' : implode(', ', $audience)],
            ['Expires in' => sprintf('%d seconds', $token->expiresIn)],
            ['Token id' => $token->jti],
        );

        return Command::SUCCESS;
    }

    /**
     * One issuer is used without being named, the way `jwt:token:inspect` uses
     * one consumer: an application that mints from a single issuer should not
     * have to spell its name at every call, whatever that name happens to be.
     * `default` breaks a tie because it is the name the autowiring alias
     * already treats as the ordinary one.
     *
     * @param list<string> $configured
     */
    private static function theIssuer(array $configured): ?string
    {
        if (1 === count($configured)) {
            return $configured[0];
        }

        return in_array('default', $configured, true) ? 'default' : null;
    }

    /**
     * An option given as an empty string is a mistake worth naming: without
     * this it is indistinguishable from one not given at all, and the command
     * would quietly mint from an issuer nobody asked for.
     */
    private static function isBlank(mixed $value): bool
    {
        return is_string($value) && '' === trim($value);
    }

    /**
     * @return array<string, string>|null null when an argument is not name=value
     */
    private static function claims(InputInterface $input): ?array
    {
        $claims = [];

        foreach (self::strings($input, 'claim') as $pair) {
            $parts = explode('=', $pair, 2);

            if (2 !== count($parts) || '' === $parts[0]) {
                return null;
            }

            $claims[$parts[0]] = $parts[1];
        }

        return $claims;
    }

    /**
     * @return int|false|null false when the option is present but not a positive integer
     */
    private static function ttl(InputInterface $input): int|false|null
    {
        $ttl = self::string($input, 'ttl');

        if (null === $ttl) {
            return null;
        }

        return 1 === preg_match('/^[1-9]\d*$/', $ttl) ? (int) $ttl : false;
    }

    /**
     * @return list<string>
     */
    private static function strings(InputInterface $input, string $option): array
    {
        $values = $input->getOption($option);

        return is_array($values) ? array_values(array_filter($values, is_string(...))) : [];
    }

    private static function string(InputInterface $input, string $name): ?string
    {
        $value = 'subject' === $name ? $input->getArgument($name) : $input->getOption($name);

        return is_string($value) && '' !== $value ? $value : null;
    }

    /**
     * @param list<string> $names
     */
    private static function listOf(array $names): string
    {
        return [] === $names ? 'none' : '"' . implode('", "', $names) . '"';
    }
}
