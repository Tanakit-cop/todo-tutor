<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\TodoController;
use App\Models\Todo;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;

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

Route::get('/hello', function() {
    return 'hello world';
});

Route::get('/hello', function() {
    return 'hello world';
});

Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);


Route::group(['middleware' => ['auth:sanctum']], function() {
    Route::get('/todo' , [TodoController::class, 'index']);
    Route::get('/todo/{id}' , [TodoController::class, 'show']); 
    Route::post('/todo' , [TodoController::class, 'store']);
    Route::put('/todo/{id}' , [TodoController::class, 'update']);
    Route::delete('/todo/{id}' , [TodoController::class, 'destroy']);

    Route::post('/logout', [AuthController::class, 'logout']);
});



Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});
