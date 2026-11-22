<?php

declare(strict_types=1);

namespace App\Http\Controllers\Auth;

use App\Actions\User\CreateUser;
use App\Enums\Auth\SocialAuthProvider;
use App\Http\Controllers\Auth\Concerns\PreservesAttributionParameters;
use App\Http\Controllers\Auth\Concerns\PreservesInvite;
use App\Http\Controllers\Auth\Concerns\PreservesSignupPreferences;
use App\Http\Controllers\Controller;
use App\Models\Invite;
use App\Models\User;
use App\Socialite\Zoho\ZohoAuthenticationException;
use App\Socialite\Zoho\ZohoDirectorySettings;
use Illuminate\Auth\Events\Registered;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Laravel\Socialite\Contracts\User as SocialiteUser;
use Laravel\Socialite\Facades\Socialite;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Throwable;

/**
 * Zoho Directory single sign-on.
 *
 * Unlike the Google/GitHub flows, a Zoho identity is never attached to an
 * existing account by email alone: guests are matched only by the stored
 * Zoho subject (`zoho_id`), and linking happens from Profile → Login while
 * signed in, only when the verified Zoho email equals the account email.
 */
class ZohoController extends Controller
{
    use PreservesAttributionParameters, PreservesInvite, PreservesSignupPreferences;

    public function redirect(Request $request): RedirectResponse
    {
        abort_unless(SocialAuthProvider::Zoho->isEnabled(), 404);

        $this->storeAttributionParameters($request);
        $this->storeInvite($request);
        $this->storeSignupPreferences($request);

        return Socialite::driver('zoho')->redirect();
    }

    public function callback(Request $request): RedirectResponse
    {
        abort_unless(SocialAuthProvider::Zoho->isEnabled(), 404);

        $linking = Auth::check();

        try {
            $zohoUser = Socialite::driver('zoho')->user();
        } catch (ZohoAuthenticationException $e) {
            Log::warning('Zoho sign-in rejected', ['reason' => $e->reason]);

            return $this->failure($linking, __('auth.zoho_failed'));
        } catch (Throwable $e) {
            Log::warning('Zoho sign-in failed', ['reason' => class_basename($e)]);

            return $this->failure($linking, __('auth.zoho_failed'));
        }

        $email = strtolower((string) $zohoUser->getEmail());

        if (! ZohoDirectorySettings::fromConfig()?->allowsEmail($email)) {
            Log::warning('Zoho sign-in rejected', ['reason' => 'domain-not-allowed']);

            return $this->failure($linking, __('auth.zoho_not_allowed'));
        }

        if ($linking) {
            return $this->linkToCurrentUser($request->user(), $zohoUser, $email);
        }

        $user = User::query()->where('zoho_id', $zohoUser->getId())->first();

        if ($user) {
            return $this->loginExistingUser($user);
        }

        if (User::query()->whereRaw('lower(email) = ?', [$email])->exists()) {
            $this->discardOAuthSession();

            return redirect()->route('login')->withErrors(['email' => __('auth.zoho_link_required')]);
        }

        return $this->registerNewUser($zohoUser, $email);
    }

    private function linkToCurrentUser(User $user, SocialiteUser $zohoUser, string $email): RedirectResponse
    {
        $this->discardOAuthSession();
        $profile = redirect()->route('app.profile.edit', ['tab' => 'login']);

        if (strtolower((string) $user->email) !== $email) {
            return $profile->with('flash.error', __('settings.profile.providers.flash_email_mismatch', ['provider' => 'Zoho']));
        }

        $linkedElsewhere = User::query()
            ->where('zoho_id', $zohoUser->getId())
            ->whereKeyNot($user->getKey())
            ->exists();

        if ($linkedElsewhere) {
            return $profile->with('flash.error', __('settings.profile.providers.flash_already_linked', ['provider' => 'Zoho']));
        }

        if ($user->zoho_id !== $zohoUser->getId()) {
            $user->update(['zoho_id' => $zohoUser->getId()]);
        }

        return $profile->with('flash.success', __('settings.profile.providers.flash_connected', ['provider' => 'Zoho']));
    }

    private function loginExistingUser(User $user): RedirectResponse
    {
        Auth::login($user, remember: true);

        $this->retrieveAttributionParameters();
        $this->retrieveSignupPreferences();

        if ($invite = Invite::fromId($this->retrieveInvite())) {
            return redirect()->route('app.invites.show', $invite);
        }

        return redirect()->intended(route('app.calendar'));
    }

    private function registerNewUser(SocialiteUser $zohoUser, string $email): RedirectResponse
    {
        try {
            // Self-hosted: same rule as /register — only with a valid invite.
            $invite = $this->resolveInviteForRegistration();
        } catch (NotFoundHttpException) {
            $this->discardOAuthSession();

            return redirect()->route('login')->withErrors(['email' => __('auth.zoho_no_account')]);
        }

        if ($redirect = $this->inviteEmailMismatchRedirect($invite, $email)) {
            return $redirect;
        }

        $attributionParameters = $this->retrieveAttributionParameters();
        $preferences = $this->retrieveSignupPreferences();

        $user = CreateUser::execute([
            'name' => $zohoUser->getName() ?: strstr($email, '@', true),
            'email' => $email,
            'zoho_id' => $zohoUser->getId(),
            // Zoho asserted email_verified=true for an allowlisted domain.
            'email_verified_at' => now(),
            'is_invite' => $invite !== null,
            'registration_ip' => request()->ip(),
            'locale' => data_get($preferences, 'locale'),
            'timezone' => data_get($preferences, 'timezone'),
            'week_starts_on' => data_get($preferences, 'week_starts_on'),
            'time_format' => data_get($preferences, 'time_format'),
        ], $attributionParameters);

        event(new Registered($user));

        Auth::login($user, remember: true);

        if ($invite) {
            return redirect()->route('app.invites.show', $invite);
        }

        return redirect()->route('app.welcome');
    }

    private function failure(bool $linking, string $message): RedirectResponse
    {
        $this->discardOAuthSession();

        if ($linking) {
            return redirect()->route('app.profile.edit', ['tab' => 'login'])->with('flash.error', $message);
        }

        return redirect()->route('login')->withErrors(['email' => $message]);
    }

    /** Drops the values stored by redirect() so they cannot leak into a later sign-in. */
    private function discardOAuthSession(): void
    {
        $this->retrieveAttributionParameters();
        $this->retrieveSignupPreferences();
        $this->retrieveInvite();
    }
}
