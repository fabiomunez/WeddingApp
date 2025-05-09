<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\Role;
use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Laravel\Socialite\Facades\Socialite;

class SocialAuthController extends Controller
{
    /**
     * Get the authentication URL for the provider.
     *
     * @param string $provider
     * @return \Illuminate\Http\JsonResponse
     */
    public function redirectToProvider($provider)
    {
        try {
            // Validate the provider
            if (!in_array($provider, ['google', 'facebook'])) {
                return response()->json(['error' => 'Unsupported provider'], 400);
            }
            
            // Check if provider is configured
            $config = config('services.' . $provider);
            if (empty($config)) {
                return response()->json(['error' => 'Provider configuration not found'], 400);
            }
            
            // For API-based OAuth, we'll construct the authorization URL manually
            // This avoids the session requirement
            $clientId = config('services.' . $provider . '.client_id');
            $redirectUrl = config('services.' . $provider . '.redirect');
            
            // Generate a state parameter to prevent CSRF attacks
            $state = Str::random(40);
            
            // Store the state in the response for verification in the callback
            $authUrl = '';
            
            if ($provider === 'google') {
                $authUrl = 'https://accounts.google.com/o/oauth2/auth?' . http_build_query([
                    'client_id' => $clientId,
                    'redirect_uri' => $redirectUrl,
                    'response_type' => 'code',
                    'scope' => 'openid profile email',
                    'state' => $state,
                    'access_type' => 'offline',
                ]);
            } elseif ($provider === 'facebook') {
                $authUrl = 'https://www.facebook.com/v12.0/dialog/oauth?' . http_build_query([
                    'client_id' => $clientId,
                    'redirect_uri' => $redirectUrl,
                    'response_type' => 'code',
                    'scope' => 'email',
                    'state' => $state,
                ]);
            }
            
            return response()->json([
                'url' => $authUrl,
                'state' => $state
            ]);
            
        } catch (Exception $e) {
            return response()->json([
                'error' => 'Provider not supported or misconfigured', 
                'message' => $e->getMessage()
            ], 400);
        }
    }

    /**
     * Handle the callback from the OAuth provider.
     *
     * @param Request $request
     * @param string $provider
     * @return \Illuminate\Http\JsonResponse
     */
    public function handleProviderCallback(Request $request, $provider)
    {
        try {
            // For API-based OAuth, we need to handle the token exchange manually
            $code = $request->input('code');
            if (!$code) {
                return response()->json(['error' => 'Authorization code not provided'], 400);
            }
            
            // Exchange the authorization code for an access token
            $clientId = config('services.' . $provider . '.client_id');
            $clientSecret = config('services.' . $provider . '.client_secret');
            $redirectUrl = config('services.' . $provider . '.redirect');
            
            // Make a request to the OAuth provider to exchange the code for a token
            $tokenUrl = '';
            $tokenParams = [];
            
            if ($provider === 'google') {
                $tokenUrl = 'https://oauth2.googleapis.com/token';
                $tokenParams = [
                    'client_id' => $clientId,
                    'client_secret' => $clientSecret,
                    'code' => $code,
                    'redirect_uri' => $redirectUrl,
                    'grant_type' => 'authorization_code',
                ];
            } elseif ($provider === 'facebook') {
                $tokenUrl = 'https://graph.facebook.com/v12.0/oauth/access_token';
                $tokenParams = [
                    'client_id' => $clientId,
                    'client_secret' => $clientSecret,
                    'code' => $code,
                    'redirect_uri' => $redirectUrl,
                ];
            }
            
            $client = new \GuzzleHttp\Client();
            $response = $client->post($tokenUrl, [
                'form_params' => $tokenParams,
                'headers' => [
                    'Accept' => 'application/json',
                ],
            ]);
            
            $tokenData = json_decode($response->getBody(), true);
            $accessToken = $tokenData['access_token'] ?? null;
            
            if (!$accessToken) {
                return response()->json(['error' => 'Failed to obtain access token'], 400);
            }
            
            // Get user information from the provider using the access token
            $userInfoUrl = '';
            $userInfoParams = [];
            
            if ($provider === 'google') {
                $userInfoUrl = 'https://www.googleapis.com/oauth2/v3/userinfo';
                $userInfoParams = ['access_token' => $accessToken];
            } elseif ($provider === 'facebook') {
                $userInfoUrl = 'https://graph.facebook.com/v12.0/me';
                $userInfoParams = [
                    'access_token' => $accessToken,
                    'fields' => 'id,name,email,picture',
                ];
            }
            
            $userInfoResponse = $client->get($userInfoUrl, [
                'query' => $userInfoParams,
                'headers' => [
                    'Accept' => 'application/json',
                ],
            ]);
            
            $userData = json_decode($userInfoResponse->getBody(), true);
            
            // Map the provider's user data to our application's user model
            $providerId = $userData['id'] ?? ($userData['sub'] ?? null);
            $name = $userData['name'] ?? null;
            $email = $userData['email'] ?? null;
            $avatar = '';
            
            if ($provider === 'google') {
                $avatar = $userData['picture'] ?? null;
            } elseif ($provider === 'facebook') {
                $avatar = $userData['picture']['data']['url'] ?? null;
            }
            
            if (!$providerId || !$email) {
                return response()->json(['error' => 'Failed to get user information from provider'], 400);
            }
            
            // Find or create the user in our database
            $user = User::where('provider_id', $providerId)
                        ->orWhere('email', $email)
                        ->first();

            if (!$user) {
                $user = User::create([
                    'name' => $name,
                    'email' => $email,
                    'provider' => $provider,
                    'provider_id' => $providerId,
                    'avatar' => $avatar,
                    'password' => Hash::make(Str::random(16)), // Random password
                ]);

                // Assign default 'guest' role
                $role = Role::where('name', 'guest')->first();
                if ($role) {
                    $user->roles()->attach($role->id);
                }
            } else {
                // Update existing user with provider info if needed
                if (!$user->provider || !$user->provider_id) {
                    $user->update([
                        'provider' => $provider,
                        'provider_id' => $providerId,
                        'avatar' => $avatar,
                    ]);
                }
            }

            // Create token for API authentication
            $token = $user->createToken('auth_token')->plainTextToken;

            return response()->json([
                'message' => 'Social login successful',
                'user' => $user->load('roles'),
                'token' => $token,
            ]);
        } catch (Exception $e) {
            return response()->json([
                'error' => 'Failed to authenticate with social provider', 
                'message' => $e->getMessage()
            ], 500);
        }
    }
}
