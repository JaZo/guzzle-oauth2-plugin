<?php

declare(strict_types=1);

namespace Sainsburys\Guzzle\Oauth2\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\HandlerStack;

abstract class TestBase extends \PHPUnit\Framework\TestCase
{
    protected ?ClientInterface $client = null;

    protected ?MockOAuth2Server $server = null;

    /**
     * @param array $options
     * @param array $serverOptions
     *
     * @return Client
     */
    protected function createClient(array $options = [], array $serverOptions = []): Client
    {
        $this->server = new MockOAuth2Server($serverOptions);
        $this->client = new Client(
            ['handler' => $this->server->getHandlerStack()] + $options
        );

        return $this->client;
    }

    /**
     * @return ClientInterface|null
     */
    protected function getClient(): ?ClientInterface
    {
        return $this->client;
    }

    /**
     * @return HandlerStack|null
     */
    protected function getHandlerStack(): ?HandlerStack
    {
        if ($this->server instanceof MockOAuth2Server) {
            return $this->server->getHandlerStack();
        }

        return null;
    }
}
