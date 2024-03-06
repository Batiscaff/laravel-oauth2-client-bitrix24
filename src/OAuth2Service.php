<?php

namespace LaravelOAuth2B24Client;

use LaravelOAuth2B24Client\Events\RefreshTokenExchanged;
use LaravelOAuth2B24Client\Models\OAuth2AccessToken;
use Fig\Http\Message\StatusCodeInterface;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Redirector;
use Illuminate\Session\SessionManager;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Auth;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessTokenInterface;
use UnexpectedValueException;

class OAuth2Service
{
    protected AbstractProvider $provider;
    protected string $providerName;

    protected SessionManager|Store $session;

    protected Redirector $redirector;

    public function __construct(AbstractProvider $provider, ?string $providerName = null)
    {
        $this->provider = $provider;
        $this->providerName = $providerName ?? self::guessProviderName($provider);

        $this->session = app('session');
        $this->redirector = app('redirect');
    }

    public function init(array $scope): RedirectResponse
    {
        $url = $this->provider->getAuthorizationUrl([
            'scope' => $scope,
        ]);

        $this->saveState($this->provider->getState());

        if ($this->pkceEnabled()) {
            $this->saveVerifier($this->getPkceVerifier());
        }

        return $this->redirector->away($url);
    }

    /**
     * @throws IdentityProviderException
     */
    public function callback(Request $request): OAuth2AccessToken
    {
        if (! $request->has('code')) {
            throw new IdentityProviderException('OAuth2 callback: code is missing', StatusCodeInterface::STATUS_BAD_REQUEST, $request->toArray());
        }

        if (! $this->hasSavedState()) {
            throw new IdentityProviderException('OAuth2 callback: state is missing', StatusCodeInterface::STATUS_BAD_REQUEST, $request->toArray());
        }

        if ($this->pkceEnabled() && ! $this->hasSavedVerifier()) {
            throw new IdentityProviderException('OAuth2 callback: verifier is missing', StatusCodeInterface::STATUS_BAD_REQUEST, $request->toArray());
        }

        if ($request->get('state') !== $this->getSavedState()) {
            throw new IdentityProviderException('OAuth2 callback: state mismatch', StatusCodeInterface::STATUS_BAD_REQUEST, $request->toArray());
        }

        $options = [
            'code' => $request->get('code'),
        ];

        if ($this->pkceEnabled()) {
            $options['code_verifier'] = $this->getSavedVerifier();
        }

        $accessToken = $this->provider->getAccessToken('authorization_code', $options);

        $this->forgetStateAndVerifier();

        return $this->getModelForToken($accessToken);
    }

    /**
     * @throws IdentityProviderException
     */
    public function exchangeRefreshToken(OAuth2AccessToken $refreshableToken): OAuth2AccessToken
    {
        $accessToken = $this->provider->getAccessToken('refresh_token', [
            'refresh_token' => $refreshableToken->getRefreshToken(),
        ]);

        $model = $this->getModelForToken($accessToken);

        $model->tokenable_type = $refreshableToken->tokenable_type;
        $model->tokenable_id = $refreshableToken->tokenable_id;

        if (empty($model->getRefreshToken())) {
            $model->refresh_token = $refreshableToken->getRefreshToken();
        }

        RefreshTokenExchanged::dispatch($refreshableToken, $model);

        return $model;
    }

    public function getProvider(): AbstractProvider
    {
        return $this->provider;
    }

    public function getResourceOwner(OAuth2AccessToken $token): ResourceOwnerInterface
    {
        return $this->provider->getResourceOwner($token->getLeagueAccessToken());
    }

    /**
     * @throws IdentityProviderException
     */
    public function api(string $subPath, $method = 'GET', $options = [], $providerName = null)
    {
        $user = Auth::user();
        $tokenModel = $user->oauth2Tokens()
            ->where('provider', $providerName ?? OAuth2Service::guessProviderName($this->provider))
            ->orderBy('expires_at', 'desc')
            ->firstOrFail()
        ;

        if ($tokenModel->hasExpired()) {
            $tokenModel = $user->getFreshAccessToken($this->provider);
        }

        $url = config('bitrix24.endpoint', '') . '/rest/' . $subPath;
        if (isset($options['query'])) {
            if (is_string($options['query'])) {
                $url .= '?' . $options['query'];
            } elseif (is_array($options['query'])) {
                $url .= '?' . http_build_query($options['query']);
            }

            unset($options['query']);
        }

        if (isset($options['body']) && is_array($options['body'])) {
            $options['body'] = http_build_query($options['body']);
        }

        $request = $this->provider->getAuthenticatedRequest($method, $url, $tokenModel->getLeagueAccessToken(), $options);
        $response = $this->provider->getParsedResponse($request);

        if (is_array($response) === false) {
            throw new UnexpectedValueException(
                'Invalid response received from Authorization Server. Expected JSON.'
            );
        }

        return $response;
    }

    public static function guessProviderName(AbstractProvider $provider): string
    {
        $class = get_class($provider);
        $parts = explode('\\', $class);

        $lastPart = array_pop($parts);
        $lastPart = rtrim($lastPart, 'Provider');

        return strtolower($lastPart);
    }

    protected function getModelForToken(AccessTokenInterface $accessToken): OAuth2AccessToken
    {
        $model = OAuth2AccessToken::fillFromAccessToken($accessToken);
        $model->provider = $this->providerName;

        return $model;
    }

    protected function saveState(string $state): void
    {
        $this->session->put($this->getStateSessionKey(), $state);
    }

    protected function hasSavedState(): bool
    {
        return $this->session->has($this->getStateSessionKey());
    }

    protected function getSavedState(): ?string
    {
        return $this->session->get($this->getStateSessionKey());
    }

    protected function pkceEnabled(): bool
    {
        return method_exists($this->provider, 'getPkceVerifier');
    }

    protected function getPkceVerifier(): ?string
    {
        return $this->provider->getPkceVerifier();
    }

    protected function saveVerifier(string $verifier)
    {
        $this->session->put($this->getVerifierSessionKey(), $verifier);
    }

    protected function hasSavedVerifier(): bool
    {
        return $this->session->has($this->getVerifierSessionKey());
    }

    protected function getSavedVerifier(): ?string
    {
        return $this->session->get($this->getVerifierSessionKey());
    }

    protected function forgetStateAndVerifier()
    {
        $this->session->forget($this->getStateSessionKey());
        $this->session->forget($this->getVerifierSessionKey());
    }

    protected function getStateSessionKey(): string
    {
        return $this->providerName . '.oauth2.state';
    }

    protected function getVerifierSessionKey(): string
    {
        return $this->providerName . '.oauth2.verifier';
    }
}
