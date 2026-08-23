<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Command;

use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
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
            ->addOption('issuer', null, InputOption::VALUE_REQUIRED, 'Name of the configured issuer to mint with', 'default')
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

                What comes out is a working credential for as long as it lives. It is on
                your screen and in your shell history; --raw keeps it out of a log file at
                least.
                HELP)
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $name = self::string($input, 'issuer') ?? 'default';

        if (!$this->issuers->has($name)) {
            $io->error(sprintf(
                'No issuer named "%s" is configured. Configured: %s.',
                $name,
                self::listOf(array_keys($this->issuers->getProvidedServices())),
            ));

            return Command::INVALID;
        }

        $claims = self::claims($input);

        if (null === $claims) {
            $io->error('Each --claim is name=value, and the name cannot be empty.');

            return Command::INVALID;
        }

        $ttl = self::ttl($input);

        if (false === $ttl) {
            $io->error('--ttl is a whole number of seconds, greater than zero.');

            return Command::INVALID;
        }

        $subject = self::string($input, 'subject') ?? '';
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
