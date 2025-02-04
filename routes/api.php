<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController; // Import the AuthController

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/
//public route
Route::post('register', [AuthController::class, 'register'])->name('user.reg');
Route::post('login', [AuthController::class, 'login'])->name('user.login');

//protected route (require authentication).
Route::middleware('auth:sanctum')->group(function() {
    Route::post('logout', [AuthController::class, 'logout'])->name('user.logout');
});
