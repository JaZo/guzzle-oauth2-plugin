<?php

declare(strict_types=1);

namespace Sainsburys\Guzzle\Oauth2;

use InvalidArgumentException;

class AccessToken
{
    protected string $token;

    protected ?\DateTime $expires = null;

    protected ?string $type;

    protected ?AccessToken $refreshToken = null;

    /** @var array<string, mixed> */
    protected array $data;

    /**
     * @param string               $token
     * @param string|null          $type  The token type (from OAuth2 key 'token_type').
     * @param array<string, mixed> $data  Other token data.
     */
    public function __construct(string $token, ?string $type, array $data = [])
    {
        $this->token = $token;
        $this->type = $type;
        $this->data = $data;
        if (isset($data['expires'])) {
            $this->expires = new \DateTime();
            $this->expires->setTimestamp((int) $data['expires']);
        } elseif (isset($data['expires_in'])) {
            $this->expires = new \DateTime();
            $this->expires->add(new \DateInterval(sprintf('PT%dS', (int) $data['expires_in'])));
        }
        if (isset($data['refresh_token'])) {
            $this->refreshToken = new self((string) $data['refresh_token'], 'refresh_token');
        }
    }

    public function isExpired(): bool
    {
        return $this->expires !== null && $this->expires->getTimestamp() < time();
    }

    public function getExpires(): ?\DateTime
    {
        return $this->expires;
    }

    /**
     * @return array<string, mixed>
     */
    public function getData(): array
    {
        return $this->data;
    }

    public function getScope(): string
    {
        return (string) ($this->data['scope'] ?? '');
    }

    public function getToken(): string
    {
        return $this->token;
    }

    public function getRefreshToken(): ?AccessToken
    {
        return $this->refreshToken;
    }

    public function getType(): ?string
    {
        return $this->type;
    }

    public function setRefreshToken(AccessToken $refreshToken): static
    {
        if ($refreshToken->getType() !== 'refresh_token') {
            throw new InvalidArgumentException(sprintf('Expected AccessToken to be "refresh_token" type, got "%s"', $refreshToken->getType()));
        }

        $this->refreshToken = $refreshToken;

        return $this;
    }
}
