<?php

use App\Http\Controllers\API\AuthController;
use App\Http\Controllers\API\SocialAuthController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// Public authentication routes
Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);

// Social authentication routes
Route::get('/auth/{provider}', [SocialAuthController::class, 'redirectToProvider']);
Route::get('/auth/{provider}/callback', [SocialAuthController::class, 'handleProviderCallback']);

// Protected routes
Route::middleware('auth:sanctum')->group(function () {
    // User info
    Route::get('/user', [AuthController::class, 'user']);
    Route::post('/logout', [AuthController::class, 'logout']);
    
    // Admin routes
    Route::middleware('role:admin')->group(function () {
        // Admin-only endpoints
        Route::get('/admin/dashboard', function () {
            return response()->json(['message' => 'Admin dashboard data']);
        });
    });
    
    // Couple routes
    Route::middleware('role:admin,couple')->group(function () {
        // Couple-only endpoints
        Route::get('/couple/dashboard', function () {
            return response()->json(['message' => 'Couple dashboard data']);
        });
    });
    
    // Vendor routes
    Route::middleware('role:admin,vendor')->group(function () {
        // Vendor-only endpoints
        Route::get('/vendor/dashboard', function () {
            return response()->json(['message' => 'Vendor dashboard data']);
        });
    });
    
    // Guest routes
    Route::middleware('role:admin,couple,guest')->group(function () {
        // Guest-only endpoints
        Route::get('/guest/dashboard', function () {
            return response()->json(['message' => 'Guest dashboard data']);
        });
    });
});
