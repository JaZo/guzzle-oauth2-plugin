<?php

declare(strict_types=1);

namespace Sainsburys\Guzzle\Oauth2\GrantType;

/**
 * Client credentials grant type.
 *
 * @link http://tools.ietf.org/html/rfc6749#section-4.4
 */
class ClientCredentials extends GrantTypeBase
{
    protected string $grantType = 'client_credentials';
}
