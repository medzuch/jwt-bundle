<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Command;

use Medzuch\Jwt\Key\EcPrivateKey;
use Medzuch\Jwt\Key\OkpPrivateKey;
use Medzuch\Jwt\Key\RsaPrivateKey;
use Medzuch\JwtBundle\Algorithm\SigningAlgorithms;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Generates a key the bundle can be configured with, and prints the
 * configuration that would use it.
 *
 * The snippet is the point. Generating a keypair is a line of `openssl`; what
 * costs an afternoon is which of the four key sources it belongs in, whether
 * the halves go in one entry or two, and what a `kid` has to match. So the
 * command ends with a block that can be pasted, and the material it names is
 * built through the library — a key this prints is a key the bundle loads.
 *
 * Private material is written with mode 0600 and never overwrites: a key file
 * that appears where one already existed has invalidated every token in flight,
 * and the second run is the one that would do it silently.
 */
#[AsCommand(
    name: 'jwt:key:generate',
    description: 'Generate a signing key and print the configuration that uses it',
)]
final class GenerateKeyCommand extends Command
{
    private const FORMAT_PEM = 'pem';
    private const FORMAT_JWK = 'jwk';

    /** RFC 8725 §3.5: an HMAC secret is at least as long as the hash it feeds. */
    private const SECRET_BYTES = ['HS256' => 32, 'HS384' => 48, 'HS512' => 64];

    private const CURVES = ['ES256' => 'prime256v1', 'ES384' => 'secp384r1', 'ES512' => 'secp521r1'];

    protected function configure(): void
    {
        $this
            ->addArgument('algorithm', InputArgument::REQUIRED, sprintf('JOSE "alg" the key is bound to: %s', implode(', ', SigningAlgorithms::names())))
            ->addOption('kid', null, InputOption::VALUE_REQUIRED, 'Key id to bind the key to. Rotation needs one; a key generated without it is published without it')
            ->addOption('name', null, InputOption::VALUE_REQUIRED, 'Key name in the printed configuration, and the stem of the written files', 'default')
            ->addOption('format', null, InputOption::VALUE_REQUIRED, sprintf('"%s" or "%s". EdDSA is JWK only', self::FORMAT_PEM, self::FORMAT_JWK), self::FORMAT_PEM)
            ->addOption('out', null, InputOption::VALUE_REQUIRED, 'Directory to write the key files into instead of printing them')
            ->addOption('bits', null, InputOption::VALUE_REQUIRED, 'RSA modulus size in bits', '2048')
            ->setHelp(<<<'HELP'
                Generates one key and prints the medzuch_jwt configuration that uses it.

                  <info>%command.full_name% RS256 --kid 2026-08 --out config/jwt</info>
                  <info>%command.full_name% EdDSA --kid 2026-08 --name signing</info>
                  <info>%command.full_name% HS256</info>

                Without --out the material is printed, which puts a private key in the
                terminal and its scrollback. With --out it is written to files, the private
                one readable only by its owner, and neither is ever overwritten.

                A shared secret is printed as an environment line rather than a file: that
                is where the "hmac" source reads it from.
                HELP)
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $algorithm = $input->getArgument('algorithm');
        $algorithm = is_string($algorithm) ? $algorithm : '';
        $name = self::option($input, 'name') ?? 'default';
        $kid = self::option($input, 'kid');
        $format = self::option($input, 'format') ?? self::FORMAT_PEM;
        $out = self::option($input, 'out');

        if (!in_array($algorithm, SigningAlgorithms::names(), true)) {
            $io->error(sprintf('Unknown algorithm "%s". This bundle signs with: %s.', $algorithm, implode(', ', SigningAlgorithms::names())));

            return Command::INVALID;
        }

        if (!in_array($format, [self::FORMAT_PEM, self::FORMAT_JWK], true)) {
            $io->error(sprintf('Unknown format "%s". Give "%s" or "%s".', $format, self::FORMAT_PEM, self::FORMAT_JWK));

            return Command::INVALID;
        }

        try {
            $family = SigningAlgorithms::familyOf($algorithm);

            // An option the algorithm cannot use is refused rather than
            // ignored. The alternative — accepting it quietly — teaches that
            // --format was considered, which is exactly wrong for the reader
            // who passed --format=jwk expecting a JWK.
            $unusable = self::unusableOption($input, $algorithm, $family);

            if (null !== $unusable) {
                $io->error($unusable);

                return Command::INVALID;
            }

            if (SigningAlgorithms::FAMILY_HMAC === $family) {
                return $this->generateSecret($io, $algorithm, $name, $kid, $out);
            }

            if (SigningAlgorithms::FAMILY_OKP === $family && self::FORMAT_PEM === $format) {
                $io->error(sprintf('%s has no PEM form: RFC 8037 defines the key as a JWK. Run again with --format=jwk.', $algorithm));

                return Command::INVALID;
            }

            // Only an RSA modulus has a size to give, so only there is --bits
            // read at all; every other algorithm has already refused it above.
            $bits = SigningAlgorithms::FAMILY_RSA === $family ? self::bits($input) : 0;

            $material = self::FORMAT_JWK === $format
                ? $this->jwkPair($algorithm, $kid, $bits)
                : $this->pemPair($algorithm, $bits);

            return $this->emitPair($io, $material, $algorithm, $name, $kid, $format, $out);
        } catch (\RuntimeException $failure) {
            $io->error($failure->getMessage());

            return Command::FAILURE;
        }
    }

    /**
     * A secret is neither a PEM nor a file: the `hmac` source reads it as the
     * value it is given, so what the command owes the reader is an environment
     * line and the configuration that references it.
     */
    private function generateSecret(SymfonyStyle $io, string $algorithm, string $name, ?string $kid, ?string $out): int
    {
        if (null !== $out) {
            $io->error('A shared secret is not written to a file: the "hmac" source reads the value itself, so it belongs in the environment. Run again without --out.');

            return Command::INVALID;
        }

        // base64url rather than raw bytes: the secret travels through an env
        // file, a secrets vault and a container inspection, all of which are
        // line-oriented. The encoded form is longer than the minimum it
        // encodes, so the length RFC 8725 §3.5 asks for is met by the value
        // that actually reaches HmacKey.
        $secret = self::base64Url(random_bytes(self::SECRET_BYTES[$algorithm]));
        $variable = self::environmentVariable($name);

        $io->warning('This secret both signs and verifies. It is on your screen and in your shell history.');
        $io->section('Environment');
        $io->writeln(sprintf('%s=%s', $variable, $secret));

        $this->configuration($io, $name, $algorithm, $kid, ['hmac' => sprintf("'%%env(%s)%%'", $variable)]);

        return Command::SUCCESS;
    }

    /**
     * @param array{private: string, public: string} $material
     */
    private function emitPair(SymfonyStyle $io, array $material, string $algorithm, string $name, ?string $kid, string $format, ?string $out): int
    {
        $extension = self::FORMAT_JWK === $format ? 'jwk.json' : 'pem';
        $sources = self::FORMAT_JWK === $format ? ['jwk_private', 'jwk_public'] : ['pem_private', 'pem_public'];

        if (null === $out) {
            $io->warning('The private key below signs your tokens. It is on your screen and in your scrollback; --out writes it to a file only its owner can read.');

            foreach (['private', 'public'] as $half) {
                $io->section(sprintf('%s key', ucfirst($half)));
                $io->writeln($material[$half]);
            }

            $written = [
                'private' => sprintf('config/jwt/%s.private.%s', $name, $extension),
                'public' => sprintf('config/jwt/%s.public.%s', $name, $extension),
            ];
            $io->note('The configuration below assumes you save them under config/jwt.');
        } else {
            $written = $this->write($out, $name, $extension, $material);

            $io->success(sprintf('Wrote %s and %s.', $written['private'], $written['public']));
        }

        $this->configuration($io, $name, $algorithm, $kid, [
            $sources[0] => sprintf("'%s'", self::configuredPath($written['private'])),
            $sources[1] => sprintf("'%s'", self::configuredPath($written['public'])),
        ]);

        return Command::SUCCESS;
    }

    /**
     * @param array{private: string, public: string} $material
     *
     * @return array{private: string, public: string}
     */
    private function write(string $directory, string $name, string $extension, array $material): array
    {
        // 0700, not 0755: the file mode already says the material is nobody
        // else's business, and a listable directory hands out the key names and
        // the kids in them for free.
        if (!is_dir($directory) && !@mkdir($directory, 0o700, true) && !is_dir($directory)) {
            throw new \RuntimeException(sprintf('Cannot create the directory "%s".', $directory));
        }

        $paths = [
            'private' => sprintf('%s/%s.private.%s', rtrim($directory, '/'), $name, $extension),
            'public' => sprintf('%s/%s.public.%s', rtrim($directory, '/'), $name, $extension),
        ];

        // Fails before the first file is created, so a run refused for the
        // second half leaves nothing behind.
        foreach ($paths as $path) {
            self::assertAbsent($path);
        }

        $created = [];

        try {
            foreach ($paths as $half => $path) {
                $created[] = $path;
                $this->writeHalf($path, $material[$half], 'private' === $half);
            }
        } catch (\RuntimeException $failure) {
            foreach ($created as $leftover) {
                @unlink($leftover);
            }

            throw $failure;
        }

        return $paths;
    }

    /**
     * Exclusive creation is the guarantee, for both halves: the check above
     * only buys a better message, and between it and a plain write anything can
     * appear at the path — a symlink included, which a write would follow.
     */
    private function writeHalf(string $path, string $material, bool $restricted): void
    {
        $handle = @fopen($path, 'x');

        if (false === $handle) {
            self::assertAbsent($path);

            throw new \RuntimeException(sprintf('Cannot write "%s".', $path));
        }

        try {
            // Narrowed before it holds anything: writing first and chmod-ing
            // after leaves a window in which the key is world-readable. A
            // filesystem that cannot honour the mode — a CIFS or overlay mount
            // — is a refusal, not a private key with default permissions.
            if ($restricted && !@chmod($path, 0o600)) {
                throw new \RuntimeException(sprintf('Cannot restrict "%s" to its owner, so the private key is not written. This filesystem does not carry Unix permissions.', $path));
            }

            $written = fwrite($handle, $material);

            if (false === $written || strlen($material) !== $written) {
                throw new \RuntimeException(sprintf('Cannot write "%s".', $path));
            }
        } finally {
            fclose($handle);
        }
    }

    private static function assertAbsent(string $path): void
    {
        if (file_exists($path)) {
            throw new \RuntimeException(sprintf('"%s" already exists. Refusing to replace a key: every token signed with the old one stops verifying the moment it is gone.', $path));
        }
    }

    /**
     * @return array{private: string, public: string}
     */
    private function pemPair(string $algorithm, int $bits): array
    {
        $resource = @openssl_pkey_new(self::opensslOptions($algorithm, $bits));

        if (false === $resource || !@openssl_pkey_export($resource, $private)) {
            throw new \RuntimeException(sprintf('OpenSSL could not generate an %s key: %s', $algorithm, self::opensslReason()));
        }

        $details = openssl_pkey_get_details($resource);

        if (!is_array($details) || !is_string($details['key'])) {
            throw new \RuntimeException(sprintf('OpenSSL generated an %s key it could not describe.', $algorithm));
        }

        return ['private' => (string) $private, 'public' => $details['key']];
    }

    /**
     * Every JWK the command prints is produced by the library that will read it
     * back, so a key it emits is a key the bundle loads. Ed25519 is the one
     * built by hand — there is no PEM to convert from — and it is handed
     * straight to the library, which refuses a document whose `x` disagrees
     * with its `d`.
     *
     * @return array{private: string, public: string}
     */
    private function jwkPair(string $algorithm, ?string $kid, int $bits): array
    {
        if (SigningAlgorithms::FAMILY_OKP === SigningAlgorithms::familyOf($algorithm)) {
            $seed = random_bytes(\SODIUM_CRYPTO_SIGN_SEEDBYTES);
            $public = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));

            $private = OkpPrivateKey::fromJwk(array_filter([
                'kty' => 'OKP',
                'crv' => 'Ed25519',
                'alg' => $algorithm,
                'kid' => $kid,
                'x' => self::base64Url($public),
                'd' => self::base64Url($seed),
            ], static fn(mixed $value): bool => null !== $value));

            return self::encodePair($private->toJwk(), $private->toPublicKey()->toJwk());
        }

        $pem = $this->pemPair($algorithm, $bits);

        $private = SigningAlgorithms::FAMILY_RSA === SigningAlgorithms::familyOf($algorithm)
            ? RsaPrivateKey::fromPem($pem['private'], $algorithm, $kid)
            : EcPrivateKey::fromPem($pem['private'], $algorithm, $kid);

        return self::encodePair($private->toJwk(), $private->toPublicKey()->toJwk());
    }

    /**
     * @param array<string, mixed> $private
     * @param array<string, mixed> $public
     *
     * @return array{private: string, public: string}
     */
    private static function encodePair(array $private, array $public): array
    {
        return [
            'private' => self::encode($private),
            'public' => self::encode($public + ['use' => 'sig']),
        ];
    }

    /**
     * @param array<string, mixed> $jwk
     */
    private static function encode(array $jwk): string
    {
        return json_encode($jwk, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_THROW_ON_ERROR) . "\n";
    }

    /**
     * @return array<string, mixed>
     */
    private static function opensslOptions(string $algorithm, int $bits): array
    {
        if (SigningAlgorithms::FAMILY_RSA === SigningAlgorithms::familyOf($algorithm)) {
            return ['private_key_type' => \OPENSSL_KEYTYPE_RSA, 'private_key_bits' => $bits];
        }

        return ['private_key_type' => \OPENSSL_KEYTYPE_EC, 'curve_name' => self::CURVES[$algorithm]];
    }

    /**
     * @param array<string, string> $sources
     */
    private function configuration(SymfonyStyle $io, string $name, string $algorithm, ?string $kid, array $sources): void
    {
        $lines = ['medzuch_jwt:', '    keys:', sprintf('        %s:', $name), sprintf('            algorithm: %s', $algorithm)];

        if (null !== $kid) {
            $lines[] = sprintf("            kid: '%s'", $kid);
        }

        foreach ($sources as $source => $value) {
            $lines[] = sprintf('            %s: %s', $source, $value);
        }

        $io->section('Configuration');
        $io->writeln($lines);
        $io->newLine();

        if (null === $kid) {
            $io->note('No kid: rotation needs one, because a token cannot say which of two keys on the same algorithm signed it. Re-run with --kid to bind one.');
        }
    }

    /**
     * The option this algorithm has no use for, if one was passed. Only an
     * option actually given counts: the defaults are what every run carries.
     */
    private static function unusableOption(InputInterface $input, string $algorithm, string $family): ?string
    {
        if (SigningAlgorithms::FAMILY_HMAC === $family && $input->hasParameterOption(['--format'])) {
            return sprintf('%s takes a shared secret, which has neither a PEM nor a JWK form here. --format applies to key pairs.', $algorithm);
        }

        if (SigningAlgorithms::FAMILY_RSA !== $family && $input->hasParameterOption(['--bits'])) {
            return sprintf('--bits sizes an RSA modulus, and %s has none: %s.', $algorithm, SigningAlgorithms::FAMILY_HMAC === $family
                ? 'the length of a shared secret follows from the algorithm (RFC 8725 §3.5)'
                : 'its curve is the one the algorithm names');
        }

        return null;
    }

    /**
     * What the key path looks like in the configuration.
     *
     * A relative --out is relative to where the console was run, which is the
     * project directory. The container reads the key when the key service is
     * first built, in whatever process and working directory that happens to be
     * — php-fpm's, a worker's — so a relative path copied into the
     * configuration works locally and fails on the first request that signs.
     */
    private static function configuredPath(string $path): string
    {
        return self::isAbsolute($path) ? $path : '%kernel.project_dir%/' . $path;
    }

    private static function isAbsolute(string $path): bool
    {
        return '' !== $path
            && ('/' === $path[0] || '\\' === $path[0] || 1 === preg_match('#^[a-zA-Z]:[\\\\/]#', $path));
    }

    private static function environmentVariable(string $name): string
    {
        $slug = preg_replace('/[^A-Za-z0-9]+/', '_', $name);

        return sprintf('JWT_%s_SECRET', strtoupper(is_string($slug) ? $slug : 'DEFAULT'));
    }

    private static function opensslReason(): string
    {
        $reason = openssl_error_string();

        return false === $reason || '' === $reason ? 'no reason given' : $reason;
    }

    private static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private static function option(InputInterface $input, string $name): ?string
    {
        $value = $input->getOption($name);

        return is_string($value) && '' !== $value ? $value : null;
    }

    private static function bits(InputInterface $input): int
    {
        $bits = self::option($input, 'bits') ?? '2048';

        if (!ctype_digit($bits) || (int) $bits < 2048) {
            throw new \RuntimeException(sprintf('--bits must be a whole number of at least 2048 (RFC 7518 §3.3), got "%s".', $bits));
        }

        return (int) $bits;
    }
}
