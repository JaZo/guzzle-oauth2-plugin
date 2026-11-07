<?php

declare(strict_types=1);

namespace Sainsburys\Guzzle\Oauth2\GrantType;

use Firebase\JWT\JWT;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\RequestOptions;
use InvalidArgumentException;
use Psr\Http\Message\UriInterface;
use SplFileObject;

/**
 * JSON Web Token (JWT) Bearer Token Profiles for OAuth 2.0.
 *
 * @link http://tools.ietf.org/html/draft-jones-oauth-jwt-bearer-04
 */
class JwtBearer extends GrantTypeBase
{
    public const string CONFIG_PRIVATE_KEY = 'private_key';

    protected string $grantType = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(ClientInterface $client, array $config = [])
    {
        parent::__construct($client, $config);

        if (!($this->config[self::CONFIG_PRIVATE_KEY] instanceof SplFileObject)) {
            throw new InvalidArgumentException('private_key needs to be instance of SplFileObject');
        }
    }

    protected function getRequired(): array
    {
        return array_merge(parent::getRequired(), [self::CONFIG_PRIVATE_KEY => null]);
    }

    protected function getAdditionalOptions(): array
    {
        return [
            RequestOptions::FORM_PARAMS => [
                'assertion' => $this->computeJwt(),
            ],
        ];
    }

    /**
     * Compute JWT, signing with provided private key.
     */
    protected function computeJwt(): string
    {
        $baseUri = $this->client->getConfig('base_uri');

        $payload = [
            'iss' => $this->config[self::CONFIG_CLIENT_ID],
            'aud' => sprintf('%s/%s', rtrim(($baseUri instanceof UriInterface ? (string) $baseUri : ''), '/'), ltrim((string) $this->config[self::CONFIG_TOKEN_URL], '/')),
            'exp' => time() + 60 * 60,
            'iat' => time(),
        ];

        return JWT::encode($payload, $this->readPrivateKey($this->config[self::CONFIG_PRIVATE_KEY]), 'RS256');
    }

    /**
     * Read private key.
     */
    protected function readPrivateKey(SplFileObject $privateKey): string
    {
        $key = '';
        while (!$privateKey->eof()) {
            $key .= $privateKey->fgets();
        }

        return $key;
    }
}
