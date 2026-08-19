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

RUN apk add --no-cache git unzip \
 && apk add --no-cache --virtual .build-deps $PHPIZE_DEPS linux-headers \
 && pecl install xdebug \
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

WORKDIR /app
