<?php

namespace App\Providers;

use App\Auth\CognitoGuard;
use App\Cognito\CognitoClient;
use Illuminate\Support\ServiceProvider;
use Illuminate\Foundation\Application;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;

class CognitoAuthServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $this->app->singleton(CognitoClient::class, function (Application $app) {

            $config = [
                'region'  => env('AWS_DEFAULT_REGION'),
                'version' => env('AWS_COGNITO_VERSION'),
            ];

            return new CognitoClient(
                new CognitoIdentityProviderClient($config),
                env('AWS_COGNITO_APP_CLIENT_ID'),
                env('AWS_COGNITO_USER_POOL_ID')
            );
        });

        $this->app['auth']->extend('cognito', function (Application $app, $name, array $config) {

            $guard = new CognitoGuard(
                $name,
                $client = $app->make(CognitoClient::class),
                $app['auth']->createUserProvider($config['provider']),
                $app['session.store'],
                $app['request']
            );

            $guard->setCookieJar($this->app['cookie']);
            $guard->setDispatcher($this->app['events']);
            $guard->setRequest($this->app->refresh('request', $guard, 'setRequest'));

            return $guard;
        });
    }
}
