<?php

declare(strict_types=1);

namespace Sainsburys\Guzzle\Oauth2\Middleware;

use Sainsburys\Guzzle\Oauth2\AccessToken;
use Sainsburys\Guzzle\Oauth2\GrantType\GrantTypeBase;
use Sainsburys\Guzzle\Oauth2\GrantType\GrantTypeInterface;
use Sainsburys\Guzzle\Oauth2\GrantType\RefreshTokenGrantTypeInterface;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Promise\PromiseInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class OAuthMiddleware
{
    protected ?AccessToken $accessToken = null;

    /**
     * Create a new Oauth2 subscriber.
     */
    public function __construct(
        protected ClientInterface $client,
        protected ?GrantTypeInterface $grantType = null,
        protected ?RefreshTokenGrantTypeInterface $refreshTokenGrantType = null,
    ) {
    }

    /**
     * Middleware adding the bearer token to outgoing requests.
     */
    public function onBefore(): \Closure
    {
        return function (callable $handler): \Closure {
            return function (RequestInterface $request, array $options) use ($handler): PromiseInterface {
                if ($this->isOAuthRequest($request, $options)) {
                    $token = $this->getAccessToken();
                    if ($token !== null) {
                        return $handler($request->withAddedHeader('Authorization', 'Bearer '.$token->getToken()), $options);
                    }
                }

                return $handler($request, $options);
            };
        };
    }

    /**
     * Middleware retrying requests with a new token on 401 responses.
     */
    public function onFailure(int $limit): \Closure
    {
        $calls = 0;

        return function (callable $handler) use (&$calls, $limit): \Closure {
            return function (RequestInterface $request, array $options) use ($handler, &$calls, $limit): PromiseInterface {
                /** @var PromiseInterface $promise */
                $promise = $handler($request, $options);

                return $promise->then(
                    function (ResponseInterface $response) use ($request, $options, &$calls, $limit): ResponseInterface {
                        if ($response->getStatusCode() === 401 && $this->isOAuthRequest($request, $options)) {
                            ++$calls;
                            if ($calls > $limit) {
                                return $response;
                            }

                            if ($token = $this->getAccessToken()) {
                                $response = $this->client->send($request->withHeader('Authorization', 'Bearer '.$token->getToken()), $options);
                            }
                        }

                        return $response;
                    }
                );
            };
        };
    }

    /**
     * Whether the request uses OAuth2 and is not the token request itself.
     *
     * @param array<string, mixed> $options
     */
    protected function isOAuthRequest(RequestInterface $request, array $options): bool
    {
        return ($options['auth'] ?? null) === 'oauth2'
            && $this->grantType instanceof GrantTypeInterface
            && $this->grantType->getConfigByName(GrantTypeBase::CONFIG_TOKEN_URL) !== $request->getUri()->getPath();
    }

    /**
     * Get a new access token.
     */
    protected function acquireAccessToken(): ?AccessToken
    {
        if ($this->refreshTokenGrantType) {
            // Get an access token using the stored refresh token.
            if ($this->accessToken instanceof AccessToken && $this->accessToken->getRefreshToken() instanceof AccessToken && $this->accessToken->isExpired()) {
                $this->refreshTokenGrantType->setRefreshToken($this->accessToken->getRefreshToken()->getToken());
                $this->accessToken = $this->refreshTokenGrantType->getToken();
            }
        }

        if ((!$this->accessToken || $this->accessToken->isExpired()) && $this->grantType) {
            // Get a new access token.
            $this->accessToken = $this->grantType->getToken();
        }

        return $this->accessToken;
    }

    /**
     * Get the access token.
     */
    public function getAccessToken(): ?AccessToken
    {
        if (!($this->accessToken instanceof AccessToken) || $this->accessToken->isExpired()) {
            $this->acquireAccessToken();
        }

        return $this->accessToken;
    }

    /**
     * Get the refresh token.
     */
    public function getRefreshToken(): ?AccessToken
    {
        return $this->accessToken?->getRefreshToken();
    }

    /**
     * Set the access token.
     */
    public function setAccessToken(AccessToken|string $accessToken, ?string $type = null, ?int $expires = null): static
    {
        if (is_string($accessToken)) {
            $accessToken = new AccessToken($accessToken, $type, ['expires' => $expires]);
        }
        $this->accessToken = $accessToken;

        if (
            $this->accessToken->getRefreshToken() instanceof AccessToken &&
            $this->refreshTokenGrantType instanceof RefreshTokenGrantTypeInterface
        ) {
            $this->refreshTokenGrantType->setRefreshToken($this->accessToken->getRefreshToken()->getToken());
        }

        return $this;
    }

    /**
     * Set the refresh token.
     */
    public function setRefreshToken(AccessToken|string $refreshToken): static
    {
        if (!($this->accessToken instanceof AccessToken)) {
            throw new \InvalidArgumentException('Unable to update the refresh token. You have never set first the access token.');
        }

        if (is_string($refreshToken)) {
            $refreshToken = new AccessToken($refreshToken, 'refresh_token');
        }

        $this->accessToken->setRefreshToken($refreshToken);

        if ($this->refreshTokenGrantType instanceof RefreshTokenGrantTypeInterface) {
            $this->refreshTokenGrantType->setRefreshToken($refreshToken->getToken());
        }

        return $this;
    }
}
