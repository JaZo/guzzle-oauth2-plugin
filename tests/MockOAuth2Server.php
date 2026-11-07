<?php

declare(strict_types=1);

namespace Sainsburys\Guzzle\Oauth2\Tests;


use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Psr\Http\Message\RequestInterface;

class MockOAuth2Server
{
    public const string KEY_TOKEN_EXPIRES_IN = 'tokenExpiresIn';
    public const string KEY_TOKEN_PATH = 'tokenPath';
    public const string KEY_TOKEN_INVALID_COUNT = 'tokenInvalidCount';
    public const string KEY_EXPECTED_QUERY_COUNT = 'expectedQueryCount';

    /** @var array<string, mixed> */
    protected array $options;

    private HandlerStack $handlerStack;

    private int $tokenInvalidCount = 0;

    /**
     * @param array $options
     */
    public function __construct(array $options = [])
    {
        $defaults = [
            self::KEY_TOKEN_EXPIRES_IN => 3600,
            self::KEY_TOKEN_PATH => '/oauth2/token',
            self::KEY_EXPECTED_QUERY_COUNT => 1
        ];

        $this->options = $options + $defaults;

        $handler = new MockHandler(
            $this->options[self::KEY_EXPECTED_QUERY_COUNT] > 0 ?
                array_fill(
                    0,
                    $this->options[self::KEY_EXPECTED_QUERY_COUNT],
                    function (RequestInterface $request, array $options) {
                        return $this->getResult($request, $options);
                    }
                )
                : []
        );

        $this->handlerStack = HandlerStack::create($handler);
    }

    /**
     * @return HandlerStack
     */
    public function getHandlerStack(): HandlerStack
    {
        return $this->handlerStack;
    }

    /**
     * @param RequestInterface $request
     * @param array            $options
     *
     * @throws \RuntimeException
     *
     * @return Response
     */
    protected function getResult(RequestInterface $request, array $options): Response
    {
        if ($request->getUri()->getPath() === $this->options[self::KEY_TOKEN_PATH]) {
            return $this->oauth2Token($request, $options);
        } elseif (str_contains($request->getUri()->getPath(), '/api/')) {
            return $this->mockApiCall($request);
        }

        throw new \RuntimeException('Mock server cannot handle given request URI');
    }

    /**
     * @param RequestInterface $request
     * @param array            $options
     *
     * @throws \RuntimeException
     *
     * @return Response
     */
    protected function oauth2Token(RequestInterface $request, array $options): Response
    {
        $body = $request->getBody()->__toString();
        $requestBody = [];
        parse_str($body, $requestBody);
        $grantType = $requestBody['grant_type'];
        switch ($grantType) {
            case 'password':
                return $this->grantTypePassword($requestBody);

            case 'client_credentials':
                return $this->grantTypeClientCredentials($options);

            case 'refresh_token':
                return $this->grantTypeRefreshToken($requestBody);

            case 'urn:ietf:params:oauth:grant-type:jwt-bearer':
                return $this->grantTypeJwtBearer($requestBody);
        }

        throw new \RuntimeException("Test grant type not implemented: $grantType");
    }

    /**
     * @return Response
     */
    protected function validTokenResponse(): Response
    {
        $token = [
            'access_token' => 'token',
            'refresh_token' => 'refreshToken',
            'token_type' => 'bearer',
        ];

        if (isset($this->options[self::KEY_TOKEN_INVALID_COUNT])) {
            $token['access_token'] = 'tokenInvalid';
        } elseif (isset($this->options[self::KEY_TOKEN_EXPIRES_IN])) {
            $token['expires_in'] = $this->options[self::KEY_TOKEN_EXPIRES_IN];
        }

        return new Response(200, [], json_encode($token));
    }

    /**
     * The response as expected by the MockHandler.
     *
     * @param array  $requestBody
     *
     * @return Response
     */
    protected function grantTypePassword(array $requestBody): Response
    {
        if (($requestBody['username'] ?? null) !== 'validUsername' || ($requestBody['password'] ?? null) !== 'validPassword') {
            // @todo correct response headers
            return new Response(401);
        }

        return $this->validTokenResponse();
    }

    /**
     * The response as expected by the MockHandler.
     *
     * @param array  $options
     *
     * @return Response
     */
    protected function grantTypeClientCredentials(array $options): Response
    {
        if (!isset($options['auth']) || !isset($options['auth'][1]) || $options['auth'][1] != 'testSecret') {
            // @todo correct response headers
            return new Response(401);
        }

        return $this->validTokenResponse();
    }

    /**
     * @param array  $requestBody
     *
     * @return Response
     */
    protected function grantTypeRefreshToken(array $requestBody): Response
    {
        if ($requestBody['refresh_token'] == 'refreshTokenInvalid') {
            return new Response(401);
        }

        return $this->validTokenResponse();
    }

    /**
     * @param array  $requestBody
     *
     * @return Response
     */
    protected function grantTypeJwtBearer(array $requestBody): Response
    {
        if (!array_key_exists('assertion', $requestBody)) {
            return new Response(401);
        }

        return $this->validTokenResponse();
    }

    /**
     * @param RequestInterface $request
     *
     * @return Response
     */
    protected function mockApiCall(RequestInterface $request): Response
    {
        if (
            empty($request->getHeader('Authorization')) ||
            (
                $request->getHeader('Authorization')[0] == 'Bearer tokenInvalid' &&
                isset($this->options[self::KEY_TOKEN_INVALID_COUNT]) &&
                $this->tokenInvalidCount < $this->options[self::KEY_TOKEN_INVALID_COUNT]
            )
        ) {
            if ($request->getHeader('Authorization')[0] == 'Bearer tokenInvalid') {
                ++$this->tokenInvalidCount;
            }

            return new Response(401);
        }

        return new Response(200, [], json_encode('Hello World!'));
    }
}
