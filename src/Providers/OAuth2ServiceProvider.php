<?php

namespace LaravelOAuth2B24Client\Providers;

use LaravelOAuth2B24Client\OAuth2Service;
use Illuminate\Support\ServiceProvider;
use League\OAuth2\Client\Provider\Bitrix24;

class OAuth2ServiceProvider extends ServiceProvider
{
    public function boot()
    {
        if (! class_exists('CreateOAuth2AccessTokensTable')) {
            $timestamp = date('Y_m_d_His', time());

            $this->publishes([
                __DIR__ . '/../../database/create_oauth2_access_tokens_table.php.stub' =>
                    database_path('migrations/' . $timestamp . '_create_oauth2_access_tokens_table.php'),
            ], 'migrations');
        }

        $this->publishes([
            __DIR__.'/../../config/bitrix24.php' => config_path('bitrix24.php'),
        ], 'bitrix24-config');
    }

    public function register()
    {
        if (! app()->configurationIsCached()) {
            $this->mergeConfigFrom(__DIR__ . '/../../config/bitrix24.php', 'bitrix24');
        }

        $this->app->bind('oauth2-provider', function () {
            return new Bitrix24([
                'domain'       => config('bitrix24.endpoint', ''),
                'clientId'     => config('bitrix24.client_id', ''),
                'clientSecret' => config('bitrix24.client_secret', ''),
                'redirectUri'  => config('bitrix24.redirect', ''),
            ]);
        });

        $this->app->bind('oauth2-service', function () {
            return new OAuth2Service(app('oauth2-provider'));
        });
    }
}
