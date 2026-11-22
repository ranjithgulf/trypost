<?php

declare(strict_types=1);

namespace App\Socialite\Zoho;

/**
 * Zoho Directory OIDC application settings.
 *
 * Zoho Directory serves per-application metadata at
 * `{sso_url}/.well-known/openid-configuration`: the authorize, token,
 * userinfo and keys endpoints live under the app's `/sso` path, while the
 * issuer is an organization-level Zoho Accounts URL
 * (https://accounts.zoho.<dc>/oauthapp/<org>). Both are configured
 * explicitly so nothing is derived from a guessed issuer.
 */
final readonly class ZohoDirectorySettings
{
    /**
     * @param  list<string>  $allowedDomains
     */
    public function __construct(
        public string $clientId,
        public string $clientSecret,
        public string $redirectUrl,
        public string $issuer,
        public string $ssoUrl,
        public array $allowedDomains,
    ) {}

    /**
     * Null unless every value is present and every URL is HTTPS, so a
     * half-configured deployment keeps Zoho sign-in switched off.
     */
    public static function fromConfig(): ?self
    {
        $config = (array) config('services.zoho', []);

        $clientId = trim((string) ($config['client_id'] ?? ''));
        $clientSecret = trim((string) ($config['client_secret'] ?? ''));
        $redirectUrl = self::httpsUrl($config['redirect'] ?? null);
        $issuer = self::httpsUrl($config['issuer'] ?? null);
        $ssoUrl = self::httpsUrl($config['sso_url'] ?? null);
        $allowedDomains = self::domains($config['allowed_domains'] ?? '');

        if ($clientId === '' || $clientSecret === '' || ! $redirectUrl || ! $issuer || ! $ssoUrl || $allowedDomains === []) {
            return null;
        }

        return new self($clientId, $clientSecret, $redirectUrl, $issuer, $ssoUrl, $allowedDomains);
    }

    public static function isConfigured(): bool
    {
        return self::fromConfig() !== null;
    }

    public function authorizeUrl(): string
    {
        return $this->ssoUrl.'/authorize';
    }

    public function tokenUrl(): string
    {
        return $this->ssoUrl.'/token';
    }

    public function jwksUrl(): string
    {
        return $this->ssoUrl.'/keys';
    }

    /**
     * Exact domain match (no subdomain wildcard), case-insensitive.
     */
    public function allowsEmail(string $email): bool
    {
        $email = strtolower(trim($email));
        $at = strrpos($email, '@');

        if ($at === false || $at === 0 || $at === strlen($email) - 1) {
            return false;
        }

        return in_array(substr($email, $at + 1), $this->allowedDomains, true);
    }

    private static function httpsUrl(mixed $value): ?string
    {
        $value = trim((string) $value);

        if ($value === '' || ! filter_var($value, FILTER_VALIDATE_URL) || ! str_starts_with(strtolower($value), 'https://')) {
            return null;
        }

        return rtrim($value, '/');
    }

    /**
     * @return list<string>
     */
    private static function domains(mixed $value): array
    {
        $items = is_array($value) ? $value : explode(',', (string) $value);

        return array_values(array_unique(array_filter(array_map(
            fn ($domain): string => ltrim(strtolower(trim((string) $domain)), '@'),
            $items,
        ))));
    }
}
