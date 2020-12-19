<?php

namespace App\Cognito;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;

class CognitoClient
{
    protected $client;
    protected $clientId;
    protected $poolId;

    public function __construct(CognitoIdentityProviderClient $client, $clientId, $poolId)
    {

        $this->client   = $client;
        $this->clientId = $clientId;
        $this->poolId   = $poolId;
    }

    public function authenticate($email, $password)
    {
        try {
            $response = $this->client->adminInitiateAuth([
                'AuthFlow'       => 'ADMIN_NO_SRP_AUTH',
                'AuthParameters' => [
                    'USERNAME'   => $email,
                    'PASSWORD'   => $password,
                ],
                'ClientId'       => $this->clientId,
                'UserPoolId'     => $this->poolId
            ]);

            $user = $this->client->getUser([
                'AccessToken' => data_get($response, 'AuthenticationResult.AccessToken'),
            ]);

            session()->put([
                'AuthenticationResult' => data_get($response, 'AuthenticationResult'),
                'user' => $user,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            return false;
        }

        return true;
    }
}
