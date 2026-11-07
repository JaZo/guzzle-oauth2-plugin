<?php

declare(strict_types=1);

namespace Sainsburys\Guzzle\Oauth2\GrantType;

use Sainsburys\Guzzle\Oauth2\AccessToken;

interface GrantTypeInterface
{
    /**
     * Get the token data returned by the OAuth2 server.
     */
    public function getToken(): AccessToken;

    public function getConfigByName(string $name): mixed;

    /**
     * @return array<string, mixed>
     */
    public function getConfig(): array;
}
