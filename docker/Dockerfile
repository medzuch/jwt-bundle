# Minimal dev image: official PHP CLI + composer + Xdebug.
# php:<version>-cli-alpine already ships json, openssl, sodium and mbstring —
# everything medzuch/jwt-php declares. We only add:
#   - git + unzip (so composer can install from dist)
#   - Xdebug   (loaded but off by default; toggle per-run with XDEBUG_MODE)
#   - composer (grafted from the official `composer:2` image)
#
# The supported window is PHP 8.3 and 8.4 (see composer.json). The default is
# the *floor*, because that is the version a change can break by accident;
# override to test the ceiling:
#   docker compose --profile php84 up -d php84   (see docker-compose.yml)
ARG PHP_VERSION=8.3

FROM php:${PHP_VERSION}-cli-alpine

# Xdebug is pinned so two builds a month apart produce the same image.
ARG XDEBUG_VERSION=3.5.3

RUN apk add --no-cache git unzip \
 && apk add --no-cache --virtual .build-deps $PHPIZE_DEPS linux-headers \
 && pecl install xdebug-${XDEBUG_VERSION} \
 && docker-php-ext-enable xdebug \
 && apk del --no-network .build-deps

# Xdebug 3 honours the XDEBUG_MODE env var directly, so no `xdebug.mode` line
# here — flip it per-command with `-e XDEBUG_MODE=debug|coverage`.
RUN { \
      echo 'xdebug.client_host=host.docker.internal'; \
      echo 'xdebug.client_port=9003'; \
      echo 'xdebug.start_with_request=trigger'; \
    } > /usr/local/etc/php/conf.d/xdebug.ini

COPY --from=composer:2 /usr/bin/composer /usr/local/bin/composer

# Flex, so `SYMFONY_REQUIRE=6.4.* composer update` pins a Symfony line locally
# through exactly the mechanism CI uses. Hand-listing the symfony/* packages in
# the Makefile would drift the moment a sixth component is required.
ENV COMPOSER_ALLOW_SUPERUSER=1
RUN composer global config --no-plugins allow-plugins.symfony/flex true \
 && composer global require --no-progress --no-scripts --no-plugins symfony/flex

# The bind mount belongs to the host user while the container runs as root,
# which trips git's dubious-ownership check — and composer shells out to git to
# work out the root package version, so the warning surfaces on every command.
RUN git config --global --add safe.directory /app

WORKDIR /app
