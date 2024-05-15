<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Validator;
use Illuminate\Foundation\Auth\AuthenticatesUsers;

class LoginController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles authenticating users for the application and
    | redirecting them to your home screen. The controller uses a trait
    | to conveniently provide its functionality to your applications.
    |
    */

    use AuthenticatesUsers;

    /**
     * Where to redirect users after login.
     *
     * @var string
     */
    protected $redirectTo = '/home';
    protected $maxAttempts = 2;
    protected $decayMinutes = 0.5;

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest')->except('logout');
    }

    protected function isLoginTrue(Request $request)
    {
        $credentials = $request->only($this->username(), 'password');

        return $this->guard()->attempt($credentials, $request->filled('remember'));
    }

    protected function validateLogin(Request $request)
    {
        $rules = [
            $this->username() => 'required|string',
            'password' => 'required|string',
        ];

        if($this->isCaptchaRequired($request)) {
            $rules['captcha'] = 'required|captcha';
        }

        try {
            $request->validate($rules, [
                'captcha.captcha' => 'Invalid captcha!', // Pesan kesalahan jika captcha tidak sesuai
            ]);
        } catch (\Illuminate\Validation\ValidationException $e) {

            throw $e;
        }
    }

    protected function isCaptchaRequired(Request $request)
    {
        return $this->hasTooManyLoginAttempts($request);
    }

    protected function sendLockoutResponse(Request $request)
    {
        $this->clearLoginAttempts($request);

        return back()
            ->withInput($request->only($this->username(), 'remember'))
            ->withErrors(['captcha' => 'Too many login attempts. Please enter the captcha.']);
    }

    protected function attemptLogin(Request $request)
    {
        $credentials = $this->credentials($request);

        if($this->guard()->attempt($credentials, $request->filled('remember'))) {
            return $this->sendLoginResponse($request);
        }

        if ($this->isCaptchaRequired($request)) {
            return $this->sendLockoutResponse($request);
        }

        $this->incrementLoginAttempts($request);

        return $this->sendFailedLoginResponse($request);
    }

    public function complete(Request $request)
    {        
        // Cek data registrasi di sesi
        if ($registrationData = session('registration_data')) {
            // Hapus data registrasi dari sesi
            $request->session()->forget('registration_data');

            // Tambahkan data registrasi ke input request
            $request->merge($registrationData);

            // Panggil metode register bawaan Laravel
            return $this->register($request);
        } else {
            // Redirect jika data registrasi tidak tersedia
            return redirect()->route('home')->with('error', 'Data not found');
        }
    }

}
