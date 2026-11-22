<?php

declare(strict_types=1);

namespace App\Socialite\Zoho;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Throwable;
use UnexpectedValueException;

/**
 * Verifies a Zoho Directory ID token (OIDC Core 3.1.3.7): RS256/RS384
 * signature against the application's JWKS, exp/iat, issuer, audience,
 * authorized party and nonce.
 */
class ZohoIdTokenVerifier
{
    /** `id_token_signing_alg_values_supported` in the app's discovery document. */
    private const ALGORITHMS = ['RS256', 'RS384'];

    private const LEEWAY_SECONDS = 60;

    private const JWKS_TTL_SECONDS = 3600;

    public function __construct(private readonly ZohoDirectorySettings $settings) {}

    /**
     * @return array<string, mixed> verified claims
     *
     * @throws ZohoAuthenticationException
     */
    public function verify(string $idToken, ?string $expectedNonce): array
    {
        $claims = $this->decode($idToken);

        if (($claims['iss'] ?? null) !== $this->settings->issuer) {
            throw new ZohoAuthenticationException('issuer-mismatch');
        }

        $audiences = is_array($claims['aud'] ?? null) ? $claims['aud'] : [$claims['aud'] ?? null];
        if (! in_array($this->settings->clientId, $audiences, true)) {
            throw new ZohoAuthenticationException('audience-mismatch');
        }
        if (count($audiences) > 1 && ($claims['azp'] ?? null) !== $this->settings->clientId) {
            throw new ZohoAuthenticationException('authorized-party-mismatch');
        }

        if (! is_int($claims['exp'] ?? null) || ! is_int($claims['iat'] ?? null)) {
            throw new ZohoAuthenticationException('missing-time-claims');
        }

        if (! is_string($expectedNonce) || $expectedNonce === ''
            || ! is_string($claims['nonce'] ?? null) || ! hash_equals($expectedNonce, $claims['nonce'])) {
            throw new ZohoAuthenticationException('nonce-mismatch');
        }

        if (! is_string($claims['sub'] ?? null) || $claims['sub'] === '') {
            throw new ZohoAuthenticationException('missing-subject');
        }

        return $claims;
    }

    /**
     * @return array<string, mixed>
     */
    private function decode(string $idToken): array
    {
        try {
            return $this->decodeWith($this->keySet(refresh: false), $idToken);
        } catch (UnexpectedValueException $e) {
            // An unknown `kid` usually means Zoho rotated its keys: refetch once.
            if (! str_contains($e->getMessage(), 'kid')) {
                throw new ZohoAuthenticationException('invalid-id-token', $e);
            }
        } catch (Throwable $e) {
            throw new ZohoAuthenticationException('invalid-id-token', $e);
        }

        try {
            return $this->decodeWith($this->keySet(refresh: true), $idToken);
        } catch (Throwable $e) {
            throw new ZohoAuthenticationException('invalid-id-token', $e);
        }
    }

    /**
     * @param  array<string, mixed>  $jwks
     * @return array<string, mixed>
     */
    private function decodeWith(array $jwks, string $idToken): array
    {
        $keys = array_filter(
            $jwks['keys'] ?? [],
            fn ($key): bool => is_array($key) && in_array($key['alg'] ?? 'RS256', self::ALGORITHMS, true)
                && ($key['kty'] ?? null) === 'RSA' && ($key['use'] ?? 'sig') === 'sig',
        );

        $previousLeeway = JWT::$leeway;
        JWT::$leeway = self::LEEWAY_SECONDS;

        try {
            $payload = JWT::decode($idToken, JWK::parseKeySet(['keys' => array_values($keys)], 'RS256'));
        } finally {
            JWT::$leeway = $previousLeeway;
        }

        return json_decode((string) json_encode($payload), true, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * @return array<string, mixed>
     */
    protected function keySet(bool $refresh): array
    {
        $cacheKey = 'zoho-oidc-jwks:'.sha1($this->settings->jwksUrl());

        if ($refresh) {
            Cache::forget($cacheKey);
        }

        return Cache::remember($cacheKey, self::JWKS_TTL_SECONDS, fn (): array => Http::timeout(10)
            ->acceptJson()
            ->get($this->settings->jwksUrl())
            ->throw()
            ->json());
    }
}
