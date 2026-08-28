<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\DependencyInjection;

use Medzuch\JwtBundle\Command\CheckConfigurationCommand;
use Medzuch\JwtBundle\Command\CreateTokenCommand;
use Medzuch\JwtBundle\Command\DumpJwksCommand;
use Medzuch\JwtBundle\Command\GenerateKeyCommand;
use Medzuch\JwtBundle\Command\InspectTokenCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\DependencyInjection\Loader\Configurator\ReferenceConfigurator;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service_closure;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service_locator;

/**
 * The five console commands, and the locator the two named ones reach through.
 *
 * Its own class because the console is a dependency of applications rather than
 * of bundles: everything here is skipped where `symfony/console` is not
 * installed, and that condition is easier to keep true when it guards one file.
 *
 * @internal
 */
final class ConsoleCommands
{
    /**
     * Registers nothing at all where `symfony/console` is absent: a worker image
     * that installs no way to run a command is a normal deploy, and a definition
     * for a class that cannot be loaded would break its container.
     *
     * The same rule one level down — `jwt:token:create` only where an issuer is
     * configured, `jwt:jwks:dump` only where there are keys to publish — because
     * a command whose every run ends in "nothing is configured" promises
     * something the application cannot do. `jwt:token:inspect` is registered
     * either way; it decodes without configuration.
     *
     * The two that take a name reach their subjects through a service locator
     * rather than the container: the names are known at build time, and a
     * command that could fetch anything could be asked for anything.
     *
     * @param array{keys: array<string, mixed>, issuers: array<string, mixed>, consumers: array<string, mixed>, id_tokens: array<string, mixed>, remote_jwks: array<string, mixed>, security_events: array{issuers: array<string, mixed>, consumers: array<string, mixed>}, ...} $config
     * @param array<string, array{hmac: string|null, pem_private: string|null, pem_public: string|null, jwk_private: string|null, jwk_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null}>                                                                              $keys
     * @param bool                                                                                                                                                                        $publishes whether a JWK Set service was registered to dump
     */
    public static function register(ServicesConfigurator $services, array $config, array $keys, bool $publishes): void
    {
        if (!class_exists(Command::class)) {
            return;
        }

        $issuers = array_keys($config['issuers']);
        $consumers = array_keys($config['consumers']);

        $services->set('medzuch_jwt.command.key_generate', GenerateKeyCommand::class)
            ->tag('console.command', ['command' => 'jwt:key:generate']);

        $services->set('medzuch_jwt.command.config_check', CheckConfigurationCommand::class)
            ->args([
                service_locator(self::everythingBuiltLazily($config, $keys)),
                service_locator(array_combine(
                    array_keys($config['remote_jwks']),
                    array_map(
                        static fn(string $name): ReferenceConfigurator => service('medzuch_jwt.remote_jwks.' . $name),
                        array_keys($config['remote_jwks']),
                    ),
                )),
                // A closure, so the set is built when the command asks rather
                // than when the container hands it over: a published key whose
                // file is missing is a row in the report, not an exception
                // instead of one.
                $publishes ? service_closure('medzuch_jwt.jwks.key_set') : null,
            ])
            ->tag('console.command', ['command' => 'jwt:config:check']);

        $services->set('medzuch_jwt.command.token_inspect', InspectTokenCommand::class)
            ->args([
                service_locator(array_combine(
                    $consumers,
                    array_map(static fn(string $name): ReferenceConfigurator => service('medzuch_jwt.handler.' . $name), $consumers),
                )),
                service('medzuch_jwt.clock'),
            ])
            ->tag('console.command', ['command' => 'jwt:token:inspect']);

        if ($publishes) {
            $services->set('medzuch_jwt.command.jwks_dump', DumpJwksCommand::class)
                ->args([service('medzuch_jwt.jwks.key_set')])
                ->tag('console.command', ['command' => 'jwt:jwks:dump']);
        }

        if ([] === $issuers) {
            return;
        }

        $services->set('medzuch_jwt.command.token_create', CreateTokenCommand::class)
            ->args([
                service_locator(array_combine(
                    $issuers,
                    array_map(static fn(string $name): ReferenceConfigurator => service('medzuch_jwt.issuer.' . $name), $issuers),
                )),
            ])
            ->tag('console.command', ['command' => 'jwt:token:create']);
    }

    /**
     * What the container builds only when something asks for it, keyed by the
     * name the report calls it. Key material above all: a `pem_private` is a
     * path or an env reference until a factory reads it, so a file nobody
     * deployed is a configuration that compiles and a request that does not.
     *
     * @param array{keys: array<string, mixed>, issuers: array<string, mixed>, consumers: array<string, mixed>, id_tokens: array<string, mixed>, security_events: array{issuers: array<string, mixed>, consumers: array<string, mixed>}, ...} $config
     * @param array<string, array{hmac: string|null, pem_private: string|null, pem_public: string|null, jwk_private: string|null, jwk_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null}>                                        $keys
     *
     * @return array<string, ReferenceConfigurator>
     */
    private static function everythingBuiltLazily(array $config, array $keys): array
    {
        $subjects = [];

        foreach ($keys as $name => $key) {
            if (null !== $key['hmac']) {
                // One row, because there is one key: a shared secret is both
                // halves, and `.signing` and `.verification` are aliases to it.
                // Reported twice, one bad secret would read as two mistakes.
                $subjects[sprintf('key "%s"', $name)] = service('medzuch_jwt.key.' . $name);

                continue;
            }

            foreach (['signing' => KeyEntries::hasPrivateHalf($key), 'verification' => KeyEntries::hasPublicHalf($key)] as $half => $configured) {
                if ($configured) {
                    $subjects[sprintf('key "%s" (%s)', $name, $half)] = service(sprintf('medzuch_jwt.key.%s.%s', $name, $half));
                }
            }
        }

        foreach (array_keys($config['consumers']) as $name) {
            // The handler rather than the consumer: it is what the firewall
            // calls, so building it also builds the user resolver and the
            // denylist behind it.
            $subjects[sprintf('consumer "%s"', $name)] = service('medzuch_jwt.handler.' . $name);
        }

        foreach (array_keys($config['issuers']) as $name) {
            $subjects[sprintf('issuer "%s"', $name)] = service('medzuch_jwt.issuer.' . $name);
        }

        foreach (array_keys($config['id_tokens']) as $name) {
            $subjects[sprintf('ID token "%s"', $name)] = service('medzuch_jwt.id_token.' . $name);
        }

        foreach (array_keys($config['security_events']['issuers']) as $name) {
            $subjects[sprintf('security event stream "%s"', $name)] = service('medzuch_jwt.security_event_issuer.' . $name);
        }

        foreach (array_keys($config['security_events']['consumers']) as $name) {
            $subjects[sprintf('security event consumer "%s"', $name)] = service('medzuch_jwt.security_event_consumer.' . $name);
        }

        return $subjects;
    }
}
