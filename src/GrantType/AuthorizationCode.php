<?php

declare(strict_types=1);

namespace Sainsburys\Guzzle\Oauth2\GrantType;

/**
 * Authorization code grant type.
 *
 * @link http://tools.ietf.org/html/rfc6749#section-4.1
 */
class AuthorizationCode extends GrantTypeBase
{
    public const string CONFIG_REDIRECT_URI = 'redirect_uri';
    public const string CONFIG_CODE = 'code';

    protected string $grantType = 'authorization_code';

    protected function getDefaults(): array
    {
        return array_merge(parent::getDefaults(), [self::CONFIG_REDIRECT_URI => '']);
    }

    protected function getRequired(): array
    {
        return array_merge(parent::getRequired(), [self::CONFIG_CODE => '']);
    }
}
