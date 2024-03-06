<?php

namespace LaravelOAuth2B24Client\Traits;

use LaravelOAuth2B24Client\Models\OAuth2AccessToken;
use LaravelOAuth2B24Client\OAuth2Service;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use League\OAuth2\Client\Provider\AbstractProvider;

trait HasOAuth2Tokens
{
    public function oauth2Tokens(): MorphMany
    {
        return $this->morphMany(OAuth2AccessToken::class, 'tokenable');
    }

    public static function getByResourceOwnerId($resourceOwnerId, AbstractProvider $provider, ?string $providerName = null)
    {
        return self::whereHas('oauth2Tokens', function (Builder $query) use ($resourceOwnerId, $provider, $providerName) {
            $query->where('resource_owner_id', $resourceOwnerId);
            $query->where('provider', $providerName ?? OAuth2Service::guessProviderName($provider));
            $query->whereNull(OAuth2AccessToken::DELETED_AT);
        })->first();
    }

    public function getFreshAccessToken(AbstractProvider $provider, ?string $providerName = null): OAuth2AccessToken
    {
        /** @var ?OAuth2AccessToken $token */
        $token = $this->oauth2Tokens()
            ->where('provider', $providerName ?? OAuth2Service::guessProviderName($provider))
            ->orderBy('expires_at', 'desc')
            ->firstOrFail();

        if ($token->hasExpired() && $token->getRefreshToken() !== null) {
            /** @var OAuth2Service $service */
            $service = app(OAuth2Service::class, [
                'provider' => $provider,
                'providerName' => $providerName,
            ]);

            $freshToken = $service->exchangeRefreshToken($token);
            $freshToken->save();

            $token->delete();

            return $freshToken;
        }

        return $token;
    }

    public function getCurrentToken(AbstractProvider $provider, ?string $providerName = null): ?OAuth2AccessToken
    {
        return $this->oauth2Tokens()
            ->where('provider', $providerName ?? OAuth2Service::guessProviderName($provider))
            ->orderBy('expires_at', 'desc')
            ->first();
    }

    public function getResourceOwnerId(AbstractProvider $provider, ?string $providerName = null): ?string
    {
        $token = $this->getCurrentToken($provider, $providerName);

        return $token->resource_owner_id;
    }
}
