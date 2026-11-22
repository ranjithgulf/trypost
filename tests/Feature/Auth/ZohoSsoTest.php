<?php

declare(strict_types=1);

use App\Enums\Auth\SocialAuthProvider;
use App\Models\Account;
use App\Models\Invite;
use App\Models\User;
use App\Models\Workspace;
use App\Socialite\Zoho\ZohoAuthenticationException;
use App\Socialite\Zoho\ZohoDirectoryProvider;
use App\Socialite\Zoho\ZohoDirectorySettings;
use App\Socialite\Zoho\ZohoIdTokenVerifier;
use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response as GuzzleResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\InvalidStateException;
use Laravel\Socialite\Two\User as SocialiteUser;

const ZOHO_TEST_SSO = 'https://directory.zoho.com/p/948196904/app/1387085000000002056/sso';
const ZOHO_TEST_ISSUER = 'https://accounts.zoho.com/oauthapp/1002-948196904';
const ZOHO_TEST_CALLBACK = 'https://trypost.test/auth/zoho/callback';

function zohoTestEnable(array $overrides = []): void
{
    config([
        'trypost.zoho_auth_enabled' => true,
        'services.zoho' => array_merge([
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
            'redirect' => ZOHO_TEST_CALLBACK,
            'issuer' => ZOHO_TEST_ISSUER,
            'sso_url' => ZOHO_TEST_SSO,
            'allowed_domains' => 'gulfinfotech.com,zoho.cloudbegn.com',
        ], $overrides),
    ]);
}

function zohoTestSettings(): ZohoDirectorySettings
{
    zohoTestEnable();

    return ZohoDirectorySettings::fromConfig();
}

/** @return array{0: string, 1: array<string, string>} private PEM and public JWK */
function zohoTestKey(string $kid = 'k1'): array
{
    $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    openssl_pkey_export($key, $pem);
    $details = openssl_pkey_get_details($key);
    $b64 = fn (string $v): string => rtrim(strtr(base64_encode($v), '+/', '-_'), '=');

    return [$pem, [
        'kty' => 'RSA', 'alg' => 'RS256', 'use' => 'sig', 'kid' => $kid,
        'n' => $b64($details['rsa']['n']), 'e' => $b64($details['rsa']['e']),
    ]];
}

function zohoTestClaims(array $overrides = []): array
{
    return array_merge([
        'iss' => ZOHO_TEST_ISSUER,
        'aud' => 'test-client',
        'iat' => time(),
        'exp' => time() + 300,
        'nonce' => 'nonce-1',
        'sub' => 'zoho-sub-1',
        'email' => 'Ana@GulfInfoTech.com',
        'email_verified' => true,
        'name' => 'Ana Lima',
    ], $overrides);
}

function zohoTestMockDriver(SocialiteUser|Throwable $result): void
{
    $driver = Mockery::mock(AbstractProvider::class);
    $result instanceof Throwable
        ? $driver->shouldReceive('user')->andThrow($result)
        : $driver->shouldReceive('user')->andReturn($result);
    Socialite::shouldReceive('driver')->with('zoho')->andReturn($driver);
}

function zohoTestUser(string $sub, string $email, string $name = 'Ana Lima'): SocialiteUser
{
    return (new SocialiteUser)->map(['id' => $sub, 'email' => $email, 'name' => $name]);
}

// --- configuration gating ---------------------------------------------------

test('zoho is disabled unless the flag and a complete https configuration are present', function (array $overrides, bool $flag) {
    zohoTestEnable($overrides);
    config(['trypost.zoho_auth_enabled' => $flag]);

    expect(SocialAuthProvider::Zoho->isEnabled())->toBeFalse();
    $this->get(route('auth.zoho.redirect'))->assertNotFound();
    $this->get(route('auth.zoho.callback'))->assertNotFound();
})->with([
    'flag off' => [[], false],
    'no secret' => [['client_secret' => ''], true],
    'no issuer' => [['issuer' => null], true],
    'plain http sso url' => [['sso_url' => 'http://directory.zoho.com/p/1/app/2/sso'], true],
    'no allowed domains' => [['allowed_domains' => ''], true],
]);

test('login page exposes the zoho flag', function () {
    zohoTestEnable();
    $this->get(route('login'))->assertInertia(fn ($page) => $page->where('zohoAuthEnabled', true));

    config(['trypost.zoho_auth_enabled' => false]);
    $this->get(route('login'))->assertInertia(fn ($page) => $page->where('zohoAuthEnabled', false));
});

test('the callback route matches the uri registered in zoho directory', function () {
    expect(route('auth.zoho.callback', absolute: false))->toBe('/auth/zoho/callback');
});

// --- authorization request --------------------------------------------------

test('redirect sends the user to the zoho directory authorize endpoint with pkce, state and nonce', function () {
    zohoTestEnable();

    $response = $this->get(route('auth.zoho.redirect'));
    $location = $response->headers->get('Location');
    parse_str((string) parse_url($location, PHP_URL_QUERY), $query);

    expect(strtok($location, '?'))->toBe(ZOHO_TEST_SSO.'/authorize')
        ->and($query['client_id'])->toBe('test-client')
        ->and($query['redirect_uri'])->toBe(ZOHO_TEST_CALLBACK)
        ->and($query['response_type'])->toBe('code')
        ->and(explode(' ', $query['scope']))->toContain('openid', 'email', 'profile')
        ->and($query['code_challenge_method'])->toBe('S256')
        ->and($query['state'])->toBe(session('state'))
        ->and($query['nonce'])->toBe(session(ZohoDirectoryProvider::NONCE_SESSION_KEY))
        ->and(strlen($query['nonce']))->toBeGreaterThanOrEqual(32);

    $expectedChallenge = rtrim(strtr(base64_encode(hash('sha256', session('code_verifier'), true)), '+/', '-_'), '=');
    expect($query['code_challenge'])->toBe($expectedChallenge);
});

// --- ID token verification --------------------------------------------------

test('verifier accepts a correctly signed token for this application', function () {
    [$pem, $jwk] = zohoTestKey();
    $settings = zohoTestSettings();
    Http::fake([$settings->jwksUrl() => Http::response(['keys' => [$jwk]])]);

    $claims = (new ZohoIdTokenVerifier($settings))->verify(JWT::encode(zohoTestClaims(), $pem, 'RS256', 'k1'), 'nonce-1');

    expect($claims['sub'])->toBe('zoho-sub-1');
});

test('verifier rejects tokens that fail an oidc check', function (array $claims, ?string $nonce, string $reason) {
    [$pem, $jwk] = zohoTestKey();
    $settings = zohoTestSettings();
    Http::fake([$settings->jwksUrl() => Http::response(['keys' => [$jwk]])]);

    try {
        (new ZohoIdTokenVerifier($settings))->verify(JWT::encode(zohoTestClaims($claims), $pem, 'RS256', 'k1'), $nonce);
        $this->fail('expected rejection');
    } catch (ZohoAuthenticationException $e) {
        expect($e->reason)->toBe($reason);
    }
})->with([
    'other issuer' => [['iss' => 'https://accounts.zoho.com'], 'nonce-1', 'issuer-mismatch'],
    'other audience' => [['aud' => 'openreply-client'], 'nonce-1', 'audience-mismatch'],
    'multiple audiences without azp' => [['aud' => ['test-client', 'other']], 'nonce-1', 'authorized-party-mismatch'],
    'expired' => [['exp' => time() - 600, 'iat' => time() - 900], 'nonce-1', 'invalid-id-token'],
    'wrong nonce' => [['nonce' => 'attacker'], 'nonce-1', 'nonce-mismatch'],
    'no nonce in session' => [[], null, 'nonce-mismatch'],
    'no subject' => [['sub' => ''], 'nonce-1', 'missing-subject'],
]);

test('verifier rejects a token signed by a different key', function () {
    [, $jwk] = zohoTestKey();
    [$attackerPem] = zohoTestKey();
    $settings = zohoTestSettings();
    Http::fake([$settings->jwksUrl() => Http::response(['keys' => [$jwk]])]);

    (new ZohoIdTokenVerifier($settings))->verify(JWT::encode(zohoTestClaims(), $attackerPem, 'RS256', 'k1'), 'nonce-1');
})->throws(ZohoAuthenticationException::class);

test('verifier refetches the key set once when zoho rotates keys', function () {
    [, $oldJwk] = zohoTestKey('old');
    [$pem, $newJwk] = zohoTestKey('new');
    $settings = zohoTestSettings();
    Http::fake([$settings->jwksUrl() => Http::sequence()
        ->push(['keys' => [$oldJwk]])
        ->push(['keys' => [$newJwk]])]);

    $claims = (new ZohoIdTokenVerifier($settings))->verify(JWT::encode(zohoTestClaims(), $pem, 'RS256', 'new'), 'nonce-1');

    expect($claims['sub'])->toBe('zoho-sub-1');
    Http::assertSentCount(2);
});

// --- provider token exchange ------------------------------------------------

function zohoTestProvider(array $tokenResponse, array &$history, string $state = 'state-1'): ZohoDirectoryProvider
{
    $request = Request::create('/auth/zoho/callback', 'GET', ['code' => 'auth-code', 'state' => $state]);
    $session = app('session')->driver('array');
    $session->put(['state' => 'state-1', 'code_verifier' => 'verifier-123', ZohoDirectoryProvider::NONCE_SESSION_KEY => 'nonce-1']);
    $request->setLaravelSession($session);

    $stack = HandlerStack::create(new MockHandler([new GuzzleResponse(200, [], json_encode($tokenResponse))]));
    $stack->push(Middleware::history($history));

    return (new ZohoDirectoryProvider($request, 'test-client', 'test-secret', ZOHO_TEST_CALLBACK))
        ->setSettings(zohoTestSettings())
        ->setHttpClient(new Client(['handler' => $stack]));
}

test('provider exchanges the code with pkce and builds the user from the verified id token', function () {
    [$pem, $jwk] = zohoTestKey();
    Http::fake([ZOHO_TEST_SSO.'/keys' => Http::response(['keys' => [$jwk]])]);
    $history = [];
    $provider = zohoTestProvider(['access_token' => 'at', 'id_token' => JWT::encode(zohoTestClaims(), $pem, 'RS256', 'k1')], $history);

    $user = $provider->user();

    parse_str((string) $history[0]['request']->getBody(), $form);
    expect((string) $history[0]['request']->getUri())->toBe(ZOHO_TEST_SSO.'/token')
        ->and($form['code_verifier'])->toBe('verifier-123')
        ->and($form['redirect_uri'])->toBe(ZOHO_TEST_CALLBACK)
        ->and($user->getId())->toBe('zoho-sub-1')
        ->and($user->getEmail())->toBe('ana@gulfinfotech.com')
        ->and(session()->driver('array')->has(ZohoDirectoryProvider::NONCE_SESSION_KEY))->toBeFalse();
});

test('provider rejects a mismatched state before exchanging the code', function () {
    $history = [];
    zohoTestProvider(['access_token' => 'at'], $history, state: 'forged')->user();
})->throws(InvalidStateException::class);

test('provider rejects an unverified email or a missing id token', function (array $tokenResponse, string $reason) {
    [$pem, $jwk] = zohoTestKey();
    Http::fake([ZOHO_TEST_SSO.'/keys' => Http::response(['keys' => [$jwk]])]);
    $history = [];
    $tokenResponse = array_map(fn ($v) => is_array($v) ? JWT::encode($v, $pem, 'RS256', 'k1') : $v, $tokenResponse);

    try {
        zohoTestProvider($tokenResponse, $history)->user();
        $this->fail('expected rejection');
    } catch (ZohoAuthenticationException $e) {
        expect($e->reason)->toBe($reason);
    }
})->with([
    'unverified email' => [['access_token' => 'at', 'id_token' => zohoTestClaims(['email_verified' => false])], 'email-unverified'],
    'no email' => [['access_token' => 'at', 'id_token' => zohoTestClaims(['email' => null])], 'email-missing'],
    'no id token' => [['access_token' => 'at'], 'missing-id-token'],
]);

// --- sign-in decisions ------------------------------------------------------

test('a user already linked to the zoho subject signs in', function () {
    zohoTestEnable();
    $user = User::factory()->create(['email' => 'ana@gulfinfotech.com', 'zoho_id' => 'zoho-sub-1']);
    zohoTestMockDriver(zohoTestUser('zoho-sub-1', 'ana@gulfinfotech.com'));

    $this->get(route('auth.zoho.callback'))->assertRedirect(route('app.calendar'));

    $this->assertAuthenticatedAs($user);
});

test('a matching email alone never links or signs in an existing account', function () {
    zohoTestEnable();
    $user = User::factory()->create(['email' => 'ana@gulfinfotech.com', 'zoho_id' => null]);
    zohoTestMockDriver(zohoTestUser('zoho-sub-2', 'ana@gulfinfotech.com'));

    $this->get(route('auth.zoho.callback'))
        ->assertRedirect(route('login'))
        ->assertSessionHasErrors(['email' => __('auth.zoho_link_required')]);

    $this->assertGuest();
    expect($user->fresh()->zoho_id)->toBeNull();
});

test('users outside the allowed domains are rejected', function (string $email) {
    zohoTestEnable();
    zohoTestMockDriver(zohoTestUser('zoho-sub-3', $email));

    $this->get(route('auth.zoho.callback'))
        ->assertRedirect(route('login'))
        ->assertSessionHasErrors(['email' => __('auth.zoho_not_allowed')]);

    $this->assertGuest();
})->with(['ana@gmail.com', 'ana@sub.gulfinfotech.com', 'ana@gulfinfotech.com.evil.io']);

test('a failed or tampered zoho response is rejected gracefully', function () {
    zohoTestEnable();
    zohoTestMockDriver(new ZohoAuthenticationException('nonce-mismatch'));

    $this->get(route('auth.zoho.callback'))
        ->assertRedirect(route('login'))
        ->assertSessionHasErrors(['email' => __('auth.zoho_failed')]);

    $this->assertGuest();
});

test('self-hosted: a new zoho user without an invite gets no account', function () {
    zohoTestEnable();
    config(['trypost.self_hosted' => true]);
    zohoTestMockDriver(zohoTestUser('zoho-sub-4', 'new@gulfinfotech.com'));
    $before = User::query()->count();

    $this->get(route('auth.zoho.callback'))
        ->assertRedirect(route('login'))
        ->assertSessionHasErrors(['email' => __('auth.zoho_no_account')]);

    expect(User::query()->count())->toBe($before);
    $this->assertGuest();
});

test('self-hosted: an invited zoho user is registered with the zoho subject', function () {
    zohoTestEnable();
    config(['trypost.self_hosted' => true]);
    $account = Account::factory()->create();
    $owner = User::factory()->create(['account_id' => $account->id]);
    $account->update(['owner_id' => $owner->id]);
    $workspace = Workspace::factory()->create(['account_id' => $account->id, 'user_id' => $owner->id]);
    $invite = Invite::factory()->create([
        'account_id' => $account->id,
        'invited_by' => $owner->id,
        'email' => 'invitee@zoho.cloudbegn.com',
        'workspaces' => [$workspace->id],
    ]);
    zohoTestMockDriver(zohoTestUser('zoho-sub-5', 'invitee@zoho.cloudbegn.com'));

    $this->withSession(['oauth_invite_id' => $invite->id])
        ->get(route('auth.zoho.callback'))
        ->assertRedirect(route('app.invites.show', $invite));

    $user = User::query()->where('email', 'invitee@zoho.cloudbegn.com')->sole();
    expect($user->zoho_id)->toBe('zoho-sub-5')->and($user->hasVerifiedEmail())->toBeTrue();
    $this->assertAuthenticatedAs($user);
});

// --- explicit linking (signed in) -------------------------------------------

test('a signed-in user links zoho when the verified email matches', function () {
    zohoTestEnable();
    $user = User::factory()->create(['email' => 'ana@gulfinfotech.com']);
    zohoTestMockDriver(zohoTestUser('zoho-sub-6', 'ANA@gulfinfotech.com'));

    $this->actingAs($user)->get(route('auth.zoho.callback'))
        ->assertRedirect(route('app.profile.edit', ['tab' => 'login']))
        ->assertSessionHas('flash.success');

    expect($user->fresh()->zoho_id)->toBe('zoho-sub-6');
});

test('linking is refused when the zoho email differs from the account email', function () {
    zohoTestEnable();
    $user = User::factory()->create(['email' => 'bob@gulfinfotech.com']);
    zohoTestMockDriver(zohoTestUser('zoho-sub-7', 'ana@gulfinfotech.com'));

    $this->actingAs($user)->get(route('auth.zoho.callback'))
        ->assertSessionHas('flash.error', __('settings.profile.providers.flash_email_mismatch', ['provider' => 'Zoho']));

    expect($user->fresh()->zoho_id)->toBeNull();
});

test('a zoho identity already linked to someone else cannot be linked again', function () {
    zohoTestEnable();
    User::factory()->create(['email' => 'other@gulfinfotech.com', 'zoho_id' => 'zoho-sub-8']);
    $user = User::factory()->create(['email' => 'ana@gulfinfotech.com']);
    zohoTestMockDriver(zohoTestUser('zoho-sub-8', 'ana@gulfinfotech.com'));

    $this->actingAs($user)->get(route('auth.zoho.callback'))
        ->assertSessionHas('flash.error', __('settings.profile.providers.flash_already_linked', ['provider' => 'Zoho']));

    expect($user->fresh()->zoho_id)->toBeNull();
});

test('the profile connect route starts the zoho flow for a signed-in user', function () {
    zohoTestEnable();
    $user = User::factory()->create();

    $location = $this->actingAs($user)
        ->get(route('app.profile.connected-accounts.connect', 'zoho'))
        ->headers->get('Location');

    expect(strtok((string) $location, '?'))->toBe(ZOHO_TEST_SSO.'/authorize');
});

test('password login is unaffected by the zoho integration', function () {
    zohoTestEnable();
    $user = User::factory()->create(['email' => 'pw@gulfinfotech.com']);

    $this->post(route('login.store'), ['email' => 'pw@gulfinfotech.com', 'password' => 'password', 'locale' => 'en'])
        ->assertRedirect(route('app.calendar', absolute: false));

    $this->assertAuthenticatedAs($user);
});
