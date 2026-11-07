<?php

declare(strict_types=1);

namespace Sainsburys\Guzzle\Oauth2\GrantType;

use Sainsburys\Guzzle\Oauth2\AccessToken;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\RequestOptions;
use InvalidArgumentException;
use UnexpectedValueException;

abstract class GrantTypeBase implements GrantTypeInterface
{
    public const string CONFIG_TOKEN_URL = 'token_url';
    public const string CONFIG_CLIENT_ID = 'client_id';
    public const string CONFIG_CLIENT_SECRET = 'client_secret';
    public const string CONFIG_AUTH_LOCATION = 'auth_location';
    public const string CONFIG_RESOURCE = 'resource';

    public const string GRANT_TYPE = 'grant_type';

    public const string MISSING_ARGUMENT = 'The config is missing the following key: "%s"';

    /**
     * The token endpoint client.
     */
    protected ClientInterface $client;

    /**
     * @var array<string, mixed> Configuration settings
     */
    protected array $config;

    protected string $grantType = '';

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(ClientInterface $client, array $config = [])
    {
        $this->client = $client;
        $this->config = array_merge($this->getDefaults(), $config);

        foreach (array_keys($this->getRequired()) as $key) {
            if (empty($this->config[$key])) {
                throw new InvalidArgumentException(sprintf(self::MISSING_ARGUMENT, $key));
            }
        }
    }

    /**
     * Get default configuration items.
     *
     * @return array<string, mixed>
     */
    protected function getDefaults(): array
    {
        return [
            'scope' => '',
            self::CONFIG_TOKEN_URL => '/oauth2/token',
            self::CONFIG_AUTH_LOCATION => 'headers',
        ];
    }

    /**
     * Get required configuration items.
     *
     * @return array<string, mixed>
     */
    protected function getRequired(): array
    {
        return [
            self::CONFIG_CLIENT_ID => '',
        ];
    }

    /**
     * Get additional options, if any.
     *
     * @return array<string, mixed>|null
     */
    protected function getAdditionalOptions(): ?array
    {
        return null;
    }

    /**
     * @return array<string, mixed>
     */
    public function getConfig(): array
    {
        return $this->config;
    }

    public function getConfigByName(string $name): mixed
    {
        return $this->config[$name] ?? null;
    }

    public function getToken(): AccessToken
    {
        $body = $this->config;
        $body[self::GRANT_TYPE] = $this->grantType;
        unset($body[self::CONFIG_TOKEN_URL], $body[self::CONFIG_AUTH_LOCATION]);

        $requestOptions = [];

        if ($this->config[self::CONFIG_AUTH_LOCATION] !== RequestOptions::BODY) {
            $requestOptions[RequestOptions::AUTH] = [
                $this->config[self::CONFIG_CLIENT_ID],
                $this->config[self::CONFIG_CLIENT_SECRET] ?? '',
            ];
            unset($body[self::CONFIG_CLIENT_ID], $body[self::CONFIG_CLIENT_SECRET]);
        }

        $requestOptions[RequestOptions::FORM_PARAMS] = $body;

        if ($additionalOptions = $this->getAdditionalOptions()) {
            $requestOptions = array_merge_recursive($requestOptions, $additionalOptions);
        }

        $response = $this->client->request('POST', $this->config[self::CONFIG_TOKEN_URL], $requestOptions);
        $data = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);

        if (!is_array($data) || !isset($data['access_token']) || !is_string($data['access_token'])) {
            throw new UnexpectedValueException('The token endpoint response does not contain an access token.');
        }

        $tokenType = $data['token_type'] ?? null;

        return new AccessToken($data['access_token'], is_string($tokenType) ? $tokenType : null, $data);
    }
}
