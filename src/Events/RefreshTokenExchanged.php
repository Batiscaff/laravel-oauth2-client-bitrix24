<?php

namespace LaravelOAuth2B24Client\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use League\OAuth2\Client\Token\AccessTokenInterface;

class RefreshTokenExchanged
{
    use Dispatchable;
    use SerializesModels;

    public AccessTokenInterface $oldToken;
    public AccessTokenInterface $newToken;

    public function __construct(AccessTokenInterface $oldToken, AccessTokenInterface $newToken)
    {
        $this->oldToken = $oldToken;
        $this->newToken = $newToken;
    }
}
