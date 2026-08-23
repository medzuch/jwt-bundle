<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Command;

use Medzuch\Jwt\Key\JwkSet;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * Prints the JWK Set this application publishes.
 *
 * The same `JwkSet` service the endpoint serves, so what comes out here is what
 * a relying party fetches — including the refusal that matters: a symmetric key
 * never reaches this set, because the container will not build with one in
 * `medzuch_jwt.jwks`.
 *
 * Nothing but the document is printed, so it can be redirected:
 *
 *     bin/console jwt:jwks:dump > public/.well-known/jwks.json
 *
 * which is also the reason to have the command at all. An application that
 * serves its keys from a file or a CDN rather than from the endpoint needs the
 * document without needing the route, and writing it by hand is how a `kid`
 * comes to disagree with the key it names.
 */
#[AsCommand(
    name: 'jwt:jwks:dump',
    description: 'Print the public JWK Set this application publishes',
)]
final class DumpJwksCommand extends Command
{
    public function __construct(private readonly JwkSet $keys)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption('compact', null, InputOption::VALUE_NONE, 'Print it as the endpoint serves it, on one line')
            ->setHelp(<<<'HELP'
                Prints the JWK Set built from the keys under medzuch_jwt.jwks.

                  <info>%command.full_name%</info>
                  <info>%command.full_name% --compact > public/.well-known/jwks.json</info>

                Indented by default because a console is read by people; --compact prints
                the document byte for byte as medzuch_jwt.jwks_controller serves it.

                Only public halves are ever in it. Publishing a shared secret is refused
                when the container is built, not here, because the one thing a key set must
                never do is succeed at the wrong moment.
                HELP)
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        // The endpoint's own flags, named rather than guessed at: `--compact`
        // promises the bytes `medzuch_jwt.jwks_controller` returns, and a `kid`
        // carrying a slash or an angle bracket is encoded differently by
        // `JsonResponse` than by a bare `json_encode()`. Taking the constant
        // means the two cannot disagree, whatever Symfony's defaults become.
        $flags = JsonResponse::DEFAULT_ENCODING_OPTIONS | \JSON_THROW_ON_ERROR;

        if (true !== $input->getOption('compact')) {
            $flags |= \JSON_PRETTY_PRINT;
        }

        // Written raw: the document is the whole output, and a formatter would
        // decorate and wrap what is about to be redirected into a file.
        $output->writeln(json_encode($this->keys->toArray(), $flags), OutputInterface::OUTPUT_RAW);

        return Command::SUCCESS;
    }
}
