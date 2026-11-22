<?php

declare(strict_types=1);

namespace App\Enums\Auth;

use App\Socialite\Zoho\ZohoDirectorySettings;

enum SocialAuthProvider: string
{
    case Google = 'google';
    case GitHub = 'github';
    case Zoho = 'zoho';

    public function label(): string
    {
        return match ($this) {
            self::Google => 'Google',
            self::GitHub => 'GitHub',
            self::Zoho => 'Zoho',
        };
    }

    public function isEnabled(): bool
    {
        // Zoho stays off until the flag AND a complete, HTTPS-only configuration
        // (credentials, issuer, SSO URL, allowed domains) are present.
        if ($this === self::Zoho) {
            return (bool) config('trypost.zoho_auth_enabled') && ZohoDirectorySettings::isConfigured();
        }

        return (bool) config("trypost.{$this->value}_auth_enabled");
    }
}
