# Makefile — convenience wrappers around docker compose + composer.
# These are *optional*. Everything works with raw docker/composer commands too.
#
# Common targets:
#   make up          — start the container
#   make install     — composer install
#   make qa          — quality gate (CS + PHPStan + tests)
#   make qa-84       — the same gate on PHP 8.4 (own container, own vendor/)
#   make symfony V=6.4.*  — re-resolve dependencies against one Symfony line
#   make lowest      — the floor as an application installs it (CI's lowest leg)
#
# Pass extra args with ARGS="...":
#   make test ARGS="--filter=BundleBootTest"

.DEFAULT_GOAL := help

DC      := docker compose
EXEC    := $(DC) exec -T php
# PHP 8.4 lives behind a compose profile, so it never starts with plain `up`.
DC84    := $(DC) --profile php84
EXEC84  := $(DC84) exec -T php84

# Symfony line to resolve against; matches the CI matrix (see DEC-2).
V ?= 7.4.*

.PHONY: help build up down sh install update test qa qa-84 test-84 lowest phpstan cs cs-fix symfony clean

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*##"; printf "Available targets:\n\n"} \
	     /^[a-zA-Z_-]+:.*?##/ {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the dev image
	$(DC) build

up: ## Start the container in the background
	$(DC) up -d

down: ## Stop and remove the container
	$(DC) down

sh: ## Interactive shell inside the container
	$(DC) exec php sh

install: ## composer install
	$(EXEC) composer install

update: ## composer update
	$(EXEC) composer update

test: ## Run the test suite (ARGS="..." for extra phpunit args)
	$(EXEC) vendor/bin/phpunit $(ARGS)

phpstan: ## Static analysis at level 9
	$(EXEC) composer phpstan

cs: ## Check code style
	$(EXEC) composer cs:check

cs-fix: ## Apply code-style fixes
	$(EXEC) composer cs:fix

qa: ## Quality gate: style + phpstan + tests
	$(EXEC) composer qa

symfony: ## Re-resolve against one Symfony line: make symfony V=6.4.*
	$(DC) exec -T -e SYMFONY_REQUIRE=$(V) php composer update

# Tests only, like the CI leg: PHPStan reads the dependency's docblocks, and an
# old patch release states less than a current one — that is a fact about the
# release, not about this code. Leaves the container resolved at the floor;
# `make symfony V=*` puts it back.
lowest: ## The floor as an application installs it: oldest 6.4, oldest jwt-php
	$(DC) exec -T -e SYMFONY_REQUIRE=6.4.* php composer update --prefer-lowest --prefer-stable
	$(EXEC) vendor/bin/phpunit $(ARGS)

qa-84: ## Quality gate on PHP 8.4 (the ceiling of the supported window)
	$(DC84) up -d php84
	$(EXEC84) composer install
	$(EXEC84) composer qa

test-84: ## Run the test suite on PHP 8.4
	$(DC84) up -d php84
	$(EXEC84) vendor/bin/phpunit $(ARGS)

clean: ## Remove generated artefacts
	rm -rf var/ vendor/ .php-cs-fixer.cache
