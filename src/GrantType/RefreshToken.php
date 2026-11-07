<?php

declare(strict_types=1);

namespace Sainsburys\Guzzle\Oauth2\GrantType;

use Sainsburys\Guzzle\Oauth2\AccessToken;

/**
 * Refresh token grant type.
 *
 * @link http://tools.ietf.org/html/rfc6749#section-6
 */
class RefreshToken extends GrantTypeBase implements RefreshTokenGrantTypeInterface
{
    public const string CONFIG_REFRESH_TOKEN = 'refresh_token';

    protected string $grantType = 'refresh_token';

    protected function getDefaults(): array
    {
        return parent::getDefaults() + [self::CONFIG_REFRESH_TOKEN => ''];
    }

    public function setRefreshToken(string $refreshToken): void
    {
        $this->config[self::CONFIG_REFRESH_TOKEN] = $refreshToken;
    }

    public function hasRefreshToken(): bool
    {
        return !empty($this->config[self::CONFIG_REFRESH_TOKEN]);
    }

    public function getToken(): AccessToken
    {
        if (!$this->hasRefreshToken()) {
            throw new \RuntimeException('Refresh token not available');
        }

        return parent::getToken();
    }
}
