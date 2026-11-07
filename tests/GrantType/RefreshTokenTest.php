<?php

declare(strict_types=1);

namespace Sainsburys\Guzzle\Oauth2\Tests\GrantType;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Sainsburys\Guzzle\Oauth2\GrantType\RefreshToken;
use Sainsburys\Guzzle\Oauth2\Tests\TestBase;

class RefreshTokenTest extends TestBase
{
    public function testGetTokenChecksForRefreshToken(): void
    {
        $this->expectException(\RuntimeException::class);

        $grant = new RefreshToken($this->createClient(), [
            'client_id' => 'test',
        ]);
        $grant->getToken();
    }

    public function testGetConfigByName(): void
    {
        $grant = new RefreshToken($this->createClient(), [
            'client_id' => 'test',
        ]);

        $this->assertSame('test', $grant->getConfigByName('client_id'));
        $this->assertNull($grant->getConfigByName('unknown'));
    }

    public function testTokenResponseWithoutAccessTokenThrows(): void
    {
        $this->expectException(\UnexpectedValueException::class);

        $client = new Client(['handler' => HandlerStack::create(new MockHandler([
            new Response(200, [], '{"token_type":"bearer"}'),
        ]))]);
        $grant = new RefreshToken($client, [
            'client_id' => 'test',
            'refresh_token' => 'refreshToken',
        ]);
        $grant->getToken();
    }

    public function testMissingParentConfigException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The config is missing the following key: "client_id"');

        new RefreshToken($this->createClient());
    }
}
