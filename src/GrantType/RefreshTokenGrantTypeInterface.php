<?php

declare(strict_types=1);

namespace Sainsburys\Guzzle\Oauth2\GrantType;

interface RefreshTokenGrantTypeInterface extends GrantTypeInterface
{
    public function setRefreshToken(string $refreshToken): void;

    public function hasRefreshToken(): bool;
}
