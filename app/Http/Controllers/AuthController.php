<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Cookie;
use Symfony\Component\HttpFoundation\Response;

class AuthController extends Controller
{

    public function register(Request $request) {
        return User::create([
            'name' => $request->input('name'),
            'email' => $request->input('email'),
            'password' => Hash::make($request->input('password'))
        ]);
    }

    public function login(Request $request) {
        if (!Auth::attempt($request->only('email', 'password'))) {
            return response([
                'message' => 'Invalid credentials !'
            ], Response::HTTP_UNAUTHORIZED);
        }
        $user = Auth::user();

        // Create JWT Token.
        $token = $user->createToken('token')->plainTextToken;

        // Create a cookie that expires in 1 day and set the token to it.
        $cookie = cookie('jwt', $token, 60*24);

        return response([
            'message' => $token
        ])->withCookie($cookie);
    }

    public function user() {
       return Auth::user();
    }

    public function logout() {
        $cookie = Cookie::forget('jwt');

        return response([
            'message' => 'Logged out successfully !'
        ])->withCookie($cookie);
    }
}
