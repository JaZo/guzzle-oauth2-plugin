<?php

declare(strict_types=1);

namespace Sainsburys\Guzzle\Oauth2\GrantType;

/**
 * Resource owner password credentials grant type.
 *
 * @link http://tools.ietf.org/html/rfc6749#section-4.3
 */
class PasswordCredentials extends GrantTypeBase
{
    public const string CONFIG_USERNAME = 'username';
    public const string CONFIG_PASSWORD = 'password';

    protected string $grantType = 'password';

    protected function getRequired(): array
    {
        return array_merge(parent::getRequired(), [self::CONFIG_USERNAME => '', self::CONFIG_PASSWORD => '']);
    }
}
