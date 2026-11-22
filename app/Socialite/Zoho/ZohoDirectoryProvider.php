<?php

declare(strict_types=1);

namespace App\Socialite\Zoho;

use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\InvalidStateException;
use Laravel\Socialite\Two\User;

/**
 * Zoho Directory OpenID Connect (Authorization Code + PKCE S256, state and
 * nonce). The user is built from the signature-verified ID token, never
 * from unverified input.
 */
class ZohoDirectoryProvider extends AbstractProvider
{
    public const NONCE_SESSION_KEY = 'zoho_oidc_nonce';

    protected $scopes = ['openid', 'email', 'profile'];

    protected $scopeSeparator = ' ';

    protected $usesPKCE = true;

    private ?ZohoDirectorySettings $settings = null;

    public function setSettings(ZohoDirectorySettings $settings): static
    {
        $this->settings = $settings;

        return $this;
    }

    protected function settings(): ZohoDirectorySettings
    {
        return $this->settings ??= ZohoDirectorySettings::fromConfig()
            ?? throw new ZohoAuthenticationException('not-configured');
    }

    protected function verifier(): ZohoIdTokenVerifier
    {
        return new ZohoIdTokenVerifier($this->settings());
    }

    public function redirect()
    {
        $this->request->session()->put(self::NONCE_SESSION_KEY, Str::random(43));

        return parent::redirect();
    }

    protected function getAuthUrl($state): string
    {
        return $this->buildAuthUrlFromBase($this->settings()->authorizeUrl(), $state);
    }

    /**
     * @return array<string, mixed>
     */
    protected function getCodeFields($state = null): array
    {
        return array_merge(parent::getCodeFields($state), [
            'nonce' => (string) $this->request->session()->get(self::NONCE_SESSION_KEY),
        ]);
    }

    protected function getTokenUrl(): string
    {
        return $this->settings()->tokenUrl();
    }

    /**
     * @throws ZohoAuthenticationException|InvalidStateException
     */
    public function user()
    {
        if ($this->user) {
            return $this->user;
        }

        // Single use: pulled before anything else so a replay cannot reuse it.
        $nonce = $this->request->session()->pull(self::NONCE_SESSION_KEY);

        if ($this->hasInvalidState()) {
            throw new InvalidStateException;
        }

        $response = $this->getAccessTokenResponse($this->getCode());
        $idToken = Arr::get($response, 'id_token');

        if (! is_string($idToken) || $idToken === '') {
            throw new ZohoAuthenticationException('missing-id-token');
        }

        $claims = $this->verifier()->verify($idToken, is_string($nonce) ? $nonce : null);

        $email = is_string($claims['email'] ?? null) ? strtolower(trim($claims['email'])) : '';
        if ($email === '') {
            throw new ZohoAuthenticationException('email-missing');
        }

        $verified = $claims['email_verified'] ?? null;
        if ($verified !== true && $verified !== 'true') {
            throw new ZohoAuthenticationException('email-unverified');
        }

        $claims['email'] = $email;

        return $this->userInstance($response, $claims);
    }

    /**
     * Not used for sign-in (claims come from the verified ID token).
     *
     * @return array<string, mixed>
     */
    protected function getUserByToken($token): array
    {
        throw new ZohoAuthenticationException('userinfo-not-used');
    }

    /**
     * @param  array<string, mixed>  $user
     */
    protected function mapUserToObject(array $user): User
    {
        $name = $user['name'] ?? trim(($user['first_name'] ?? '').' '.($user['last_name'] ?? ''));

        return (new User)->setRaw($user)->map([
            'id' => (string) $user['sub'],
            'name' => $name !== '' ? $name : null,
            'email' => $user['email'],
            'avatar' => $user['picture'] ?? null,
        ]);
    }
}
