<?php

namespace App\Http\Controllers\Auth;

use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        return response()->json(User::latest()->get()); 
    }

    /**
     * Show the form for creating a new resource.
     */
    public function register(Request $request)
    {
        $fields = $request->validate([
            'name'=> 'required|string',
            'email'=> 'required|string|user:unique, email',
            'password'=> 'required|string'
        ]);

        $user = User::create([
            'name'=> $fields['name'],
            'email'=> $fields['email'],
            'password'=> bcrypt($fields['password'])
        ]);

        $token = $user->createToken('laravelApi')->plainTextToken;

        $response = [
            'user'=> $user,
            'token'=> $token
        ];

        return response($response, 201);
    }

    public function login(Request $request)
    {
        $fields = $request->validate([
            'email'=> 'required|string|user:unique, email',
            'password'=> 'required|string'
        ]);

        $user = User::where('email', $fields['email'])->first();

        if(!$user || !Hash::check($fields['password'], $user->password)){
            throw ValidationException::withMessages([
                'password' => ['The credentials you entered are incorrect']
            ]);
        }

        $token = $user->createToken('laravelApi')->plainTextToken;

        $response = [
            'user'=> $user,
            'token'=> $token
        ];

        return response($response, 201);
    }

}
