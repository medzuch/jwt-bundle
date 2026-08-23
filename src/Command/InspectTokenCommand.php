<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Command;

use DateTimeImmutable;
use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Jwt\ClaimsSet;
use Medzuch\Jwt\Jwt\Header;
use Medzuch\Jwt\Jwt\JwtParser;
use Medzuch\JwtBundle\Security\RejectedTokenException;
use Psr\Clock\ClockInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Input\StreamableInputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;
use Symfony\Contracts\Service\ServiceProviderInterface;

/**
 * Decodes a token, and — given a consumer — says what that consumer would make
 * of it.
 *
 * Two halves, because they answer different questions and one of them works
 * without any configuration at all. Decoding shows what is in the token,
 * verified or not, which is what you want when the token came from somewhere
 * else. Verification says whether *this* application would accept it, and names
 * the reason when it would not — the reason RFC 6750 deliberately keeps off the
 * wire.
 *
 * Verification runs the real path: the configured consumer's handler, the same
 * one the firewall calls. So a token this command calls good is a token the
 * firewall accepts, and the events an application listens for are dispatched
 * here as they would be on a request — deliberately, because an answer arrived
 * at by a second, quieter route would be worth much less.
 */
#[AsCommand(
    name: 'jwt:token:inspect',
    description: 'Decode a token and say why a consumer would refuse it',
)]
final class InspectTokenCommand extends Command
{
    /** Claims holding a moment, rendered as one rather than as a number. */
    private const INSTANTS = ['exp', 'iat', 'nbf', 'auth_time'];

    /**
     * @param ServiceProviderInterface<AccessTokenHandlerInterface> $consumers
     */
    public function __construct(
        private readonly ServiceProviderInterface $consumers,
        private readonly ClockInterface $clock,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addArgument('token', InputArgument::REQUIRED, 'The compact token, or "-" to read it from standard input')
            ->addOption('consumer', null, InputOption::VALUE_REQUIRED, 'Name of the configured consumer to verify against. Without it, one configured consumer is used and several are refused')
            ->setHelp(<<<'HELP'
                Decodes a token and, where a consumer is configured, verifies it.

                  <info>%command.full_name% eyJ0eXAiOiJhdCtqd3QiLCJhbGciOiJIUzI1NiJ9...</info>
                  <info>bin/console jwt:token:create alice --raw | bin/console %command.name% -</info>
                  <info>%command.full_name% "$TOKEN" --consumer api</info>

                The header and claims are shown whether or not anything verifies: a token
                from another issuer still decodes, and reading it is often the whole
                question. They are unverified until the verdict below them says otherwise.

                Verification asks the consumer's own handler, so the answer is the one your
                firewall would give — including the reason, which the 401 deliberately
                withholds. Your listeners see it as they would a request.

                Exit status is 0 when the token is accepted or when there was nothing to
                verify against, 1 when a consumer refuses it, and 2 when it is not a JWT.
                HELP)
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $token = self::token($input);

        if ('' === $token) {
            $io->error('No token given.');

            return Command::INVALID;
        }

        try {
            $parsed = JwtParser::parse($token);
        } catch (JwtException $failure) {
            $io->error(sprintf('This is not a JWT this bundle can read: %s', $failure->getMessage()));

            return Command::INVALID;
        }

        $this->describe($io, $parsed->header, $parsed->unverifiedClaims);

        $name = self::string($input, 'consumer') ?? self::onlyConsumer($this->consumers);

        if (null === $name) {
            return $this->withoutAConsumer($io);
        }

        if (!$this->consumers->has($name)) {
            $io->error(sprintf(
                'No consumer named "%s" is configured. Configured: %s.',
                $name,
                self::listOf(array_keys($this->consumers->getProvidedServices())),
            ));

            return Command::INVALID;
        }

        return $this->verdict($io, $name, $token);
    }

    private function verdict(SymfonyStyle $io, string $name, string $token): int
    {
        $handler = $this->consumers->get($name);

        if (!$handler instanceof AccessTokenHandlerInterface) {
            $io->error(sprintf('The service behind consumer "%s" is not an access-token handler.', $name));

            return Command::FAILURE;
        }

        try {
            $badge = $handler->getUserBadgeFrom($token);
        } catch (AuthenticationException $refusal) {
            $reason = $refusal instanceof RejectedTokenException ? $refusal->reason->value : 'other';

            $io->error(sprintf('Consumer "%s" refuses this token: %s', $name, $reason));
            $io->writeln($refusal->getMessage());

            // The library's account of what went wrong, which is the sentence
            // that usually ends the search.
            $cause = $refusal->getPrevious();

            if (null !== $cause) {
                $io->writeln($cause->getMessage());
            }

            return Command::FAILURE;
        }

        $io->success(sprintf('Consumer "%s" accepts this token.', $name));
        $io->writeln(sprintf('It would authenticate as <info>%s</info>.', $badge->getUserIdentifier()));

        return Command::SUCCESS;
    }

    private function withoutAConsumer(SymfonyStyle $io): int
    {
        $configured = array_keys($this->consumers->getProvidedServices());

        if ([] === $configured) {
            $io->note('Nothing was verified: this application configures no consumers, so the claims above are what the token says rather than what anyone accepts.');

            return Command::SUCCESS;
        }

        $io->warning(sprintf(
            'Nothing was verified: name a consumer with --consumer. Configured: %s.',
            self::listOf($configured),
        ));

        return Command::SUCCESS;
    }

    private function describe(SymfonyStyle $io, Header $header, ClaimsSet $claims): void
    {
        $io->section('Header');
        $io->definitionList(...self::rows($header->all()));

        $io->section('Claims (not verified yet)');
        $io->definitionList(...self::rows($claims->all()));
    }

    /**
     * @param array<string, mixed> $values
     *
     * @return list<array<string, string>>
     */
    private function rows(array $values): array
    {
        $rows = [];

        foreach ($values as $name => $value) {
            $rows[] = [$name => in_array($name, self::INSTANTS, true) && is_int($value)
                ? $this->moment($value)
                : self::scalar($value)];
        }

        return [] === $rows ? [['(empty)' => '']] : $rows;
    }

    /**
     * The application's clock, not the machine's: a consumer running on a
     * frozen or offset clock should have this agree with it, or "expired" here
     * and "accepted" below it would be one output contradicting itself.
     */
    private function moment(int $timestamp): string
    {
        $at = (new DateTimeImmutable())->setTimestamp($timestamp);
        $now = $this->clock->now();
        $seconds = $timestamp - $now->getTimestamp();

        return sprintf(
            '%s (%s)',
            $at->format(DATE_ATOM),
            $seconds < 0 ? sprintf('%s ago', self::duration(-$seconds)) : sprintf('in %s', self::duration($seconds)),
        );
    }

    private static function duration(int $seconds): string
    {
        if ($seconds < 90) {
            return sprintf('%d seconds', $seconds);
        }

        if ($seconds < 5400) {
            return sprintf('%d minutes', intdiv($seconds, 60));
        }

        return sprintf('%d hours', intdiv($seconds, 3600));
    }

    private static function scalar(mixed $value): string
    {
        if (is_string($value)) {
            return $value;
        }

        $json = json_encode($value, \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE);

        return false === $json ? '(unprintable)' : $json;
    }

    /**
     * One configured consumer is the common case and naming it every time would
     * be a ceremony; several are ambiguous, and picking one would answer a
     * question nobody asked.
     *
     * @param ServiceProviderInterface<AccessTokenHandlerInterface> $consumers
     */
    private static function onlyConsumer(ServiceProviderInterface $consumers): ?string
    {
        $names = array_keys($consumers->getProvidedServices());

        return 1 === count($names) ? $names[0] : null;
    }

    private static function token(InputInterface $input): string
    {
        $token = $input->getArgument('token');
        $token = is_string($token) ? trim($token) : '';

        if ('-' === $token) {
            // The input's own stream when it has one, which is what makes a
            // pipe testable; ArgvInput has none, and standard input is what a
            // pipe is.
            $stream = $input instanceof StreamableInputInterface ? $input->getStream() : null;
            $piped = stream_get_contents($stream ?? \STDIN);
            $token = is_string($piped) ? trim($piped) : '';
        }

        return $token;
    }

    private static function string(InputInterface $input, string $option): ?string
    {
        $value = $input->getOption($option);

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
