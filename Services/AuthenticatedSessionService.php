<?php

namespace Modules\Auth\Services;


use Illuminate\Auth\Events\Lockout;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Str;
use Modules\Auth\Http\Requests\LoginRequest;
use Modules\Core\Supports\Constant;

/**
 * Class AuthenticatedSessionService
 * @package Modules\Auth\Services
 */
class AuthenticatedSessionService
{
    public $request = null;

    /**
     * Handle an incoming auth request.
     *
     * @param LoginRequest $request
     * @return array
     */
    public function attemptLogin(LoginRequest $request): array
    {
        $this->request = $request;

        $authConfirmation = $this->ensureIsNotRateLimited($request);

        if ($authConfirmation['status'] == true) {
            //Count Overflow Request hit
            RateLimiter::hit($this->throttleKey($request));

            $authConfirmation = $this->authenticate($request);

            if ($authConfirmation['status'] == true) {
                //Reset Rate Limiter
                RateLimiter::clear($this->throttleKey($request));
                //start Auth session
                $request->session()->regenerate();
            }
        }

        return $authConfirmation;
    }

    /**
     * Attempt to authenticate the request's credentials.
     *
     * @param LoginRequest $request
     * @return array
     *
     */
    private function authenticate(LoginRequest $request): array
    {
        //Format config based request value
        $authInfo = $this->formatAuthCredential($request);

        $remember_me = false;

        $confirmation = ['status' => false,
            'message' => __('auth.login.failed'),
            'level' => Constant::MSG_TOASTR_ERROR,
            'title' => 'Alert!'];

        if (config('auth.allow_remembering')) {
            $remember_me = $request->boolean('remember');
        }

        //authentication is OTP
        if (!isset($authInfo['password'])) {
            $confirmation = $this->otpBasedLogin($authInfo, $remember_me);
        } //Normal Login
        else {
            $confirmation = $this->credentialBasedLogin($authInfo, $remember_me);
        }

        if ($confirmation['status'] == true) {

            //is user is banned to log in
            if (!$this->isUserEnabled()) {
                //logout from all guard
                Auth::logout();
                $confirmation = ['status' => false,
                    'message' => __('auth.login.banned'),
                    'level' => Constant::MSG_TOASTR_WARNING,
                    'title' => 'Alert!'];

            } else if ($this->hasForcePasswordReset()) {
                //redirect if password need to reset
                $confirmation = ['status' => true,
                    'message' => __('auth.login.forced'),
                    'level' => Constant::MSG_TOASTR_WARNING,
                    'title' => 'Notification!',
                    'redirect_to' => route('auth.password.reset')];

            } else {
                //set the auth user redirect page
                $confirmation['redirect_to'] = (Auth::user()->home_page ?? Constant::DASHBOARD_ROUTE);
            }
        }

        return $confirmation;
    }

    /**
     * @param array $credential
     * @param bool $remember_me
     * @return array
     */
    private function credentialBasedLogin(array $credential, bool $remember_me = false): array
    {
        $confirmation = ['status' => false, 'message' => __('auth.login.failed'), 'level' => Constant::MSG_TOASTR_ERROR, 'title' => 'Alert!'];

        if (Auth::attempt($credential, $remember_me)) {
            $confirmation = ['status' => true, 'message' => __('auth.login.success'), 'level' => Constant::MSG_TOASTR_SUCCESS, 'title' => 'Notification'];
        }

        return $confirmation;
    }

    /**
     * @param array $credential
     * @param bool $remember_me
     * @return array
     */
    private function otpBasedLogin(array $credential, bool $remember_me = false): array
    {
        $confirmation = ['status' => false, 'message' => __('auth.login.failed'), 'level' => Constant::MSG_TOASTR_ERROR, 'title' => 'Alert!'];

        if (Auth::attempt($credential, $remember_me)) {
            $confirmation = ['status' => true, 'message' => __('auth.login.success'), 'level' => Constant::MSG_TOASTR_SUCCESS, 'title' => 'Notification'];
        }

        return $confirmation;
    }

    /**
     * Ensure the login request is not rate limited.
     *
     * @param LoginRequest $request
     * @return array
     *
     */
    private function ensureIsNotRateLimited(LoginRequest $request): array
    {
        if (!RateLimiter::tooManyAttempts($this->throttleKey($request), 5)) {
            return ['status' => true, 'message' => __('auth.throttle'), 'level' => Constant::MSG_TOASTR_WARNING, 'title' => 'Warning'];
        }

        event(new Lockout($request));

        $seconds = RateLimiter::availableIn($this->throttleKey($request));

        return ['status' => false, 'message' => __('auth.throttle', [
            'seconds' => $seconds,
            'minutes' => ceil($seconds / 60),
        ]), 'level' => Constant::MSG_TOASTR_WARNING, 'title' => 'Warning'];
    }

    /**
     * Get the rate limiting throttle key for the request.
     *
     * @param LoginRequest $request
     * @return string
     */
    private function throttleKey(LoginRequest $request): string
    {
        return Str::lower($request->input('email')) . '|' . $request->ip();
    }

    /**
     * Destroy an authenticated session.
     *
     * @param Request $request
     * @return RedirectResponse
     */
    public function attemptLogout(Request $request): RedirectResponse
    {
        Auth::guard('web')->logout();

        $request->session()->invalidate();

        $request->session()->regenerateToken();

        return redirect('/');
    }

    /**
     * Verify that current request user is who he claim to be
     *
     * @param Request $request
     * @return bool
     */
    public function validate(Request $request): bool
    {
        if (config('auth.credential_field') != Constant::LOGIN_OTP) {

            $credentials = [];

            if (config('auth.credential_field') == Constant::LOGIN_EMAIL
                || (config('auth.credential_field') == Constant::LOGIN_OTP
                    && config('auth.credential_otp_field') == Constant::OTP_EMAIL)) {
                $credentials['email'] = $request->user()->email;

            } elseif (config('auth.credential_field') == Constant::LOGIN_MOBILE
                || (config('auth.credential_field') == Constant::LOGIN_OTP
                    && config('auth.credential_otp_field') == Constant::OTP_MOBILE)) {
                $credentials['mobile'] = $request->user()->mobile;

            } elseif (config('auth.credential_field') == Constant::LOGIN_USERNAME) {
                $credentials['username'] = $request->user()->username;
            }

            //Password Field
            $credentials['password'] = $request->password;

            return Auth::guard('web')->validate($credentials);
        } else {
            return true;
        }
    }

    /**
     * Collect Credential Info from Request based on Config
     *
     * @param LoginRequest $request
     * @return array
     */
    private function formatAuthCredential(LoginRequest $request): array
    {
        $credentials = [];

        if (config('auth.credential_field') == Constant::LOGIN_EMAIL
            || (config('auth.credential_field') == Constant::LOGIN_OTP
                && config('auth.credential_otp_field') == Constant::OTP_EMAIL)) {
            $credentials['email'] = $request->email;

        } elseif (config('auth.credential_field') == Constant::LOGIN_MOBILE
            || (config('auth.credential_field') == Constant::LOGIN_OTP
                && config('auth.credential_otp_field') == Constant::OTP_MOBILE)) {
            $credentials['mobile'] = $request->mobile;

        } elseif (config('auth.credential_field') == Constant::LOGIN_USERNAME) {
            $credentials['username'] = $request->username;
        }

        //Password Field
        if (config('auth.credential_field') != Constant::LOGIN_OTP) {
            $credentials['password'] = $request->password;
        }

        return $credentials;
    }

    /**
     * Verify is current user is super admin
     * @return bool
     */
    public static function isSuperAdmin(): bool
    {
        return (Auth::user()->hasRole(Constant::SUPER_ADMIN_ROLE));
    }

    /**
     * decided is if user status is disabled
     * @return bool
     */
    public function isUserEnabled(): bool
    {
        return (Auth::user()->enabled == Constant::ENABLED_OPTION);
    }

    /**
     * if user has to reset password forced
     *
     * @return bool
     */
    public function hasForcePasswordReset(): bool
    {
        return (bool)Auth::user()->force_pass_reset;
    }
}
