<?php

###############################################################################
##
##  Copyright (C) 2014, Tavendo GmbH and/or collaborators. All rights reserved.
##
##  Redistribution and use in source and binary forms, with or without
##  modification, are permitted provided that the following conditions are met:
##
##  1. Redistributions of source code must retain the above copyright notice,
##     this list of conditions and the following disclaimer.
##
##  2. Redistributions in binary form must reproduce the above copyright notice,
##     this list of conditions and the following disclaimer in the documentation
##     and/or other materials provided with the distribution.
##
##  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
##  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
##  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
##  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
##  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
##  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
##  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
##  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
##  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
##  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
##  POSSIBILITY OF SUCH DAMAGE.
##
###############################################################################

use Psr\Log\NullLogger;
use Thruway\ClientSession;
use Thruway\Authentication\ClientWampCraAuthenticator;
use Thruway\Connection;
use Thruway\Logging\Logger;
use Thruway\Message\ChallengeMessage;
use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use Sainsburys\Guzzle\Oauth2\GrantType\RefreshToken;
use Sainsburys\Guzzle\Oauth2\GrantType\PasswordCredentials;
use Sainsburys\Guzzle\Oauth2\Middleware\OAuthMiddleware;

require __DIR__ . '/vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();
Logger::set(new NullLogger());

$baseUri = $_ENV['OAUTH_BASE_URI'];
$config = [
    PasswordCredentials::CONFIG_USERNAME => $_ENV['OAUTH_USER_EMAIL'],
    PasswordCredentials::CONFIG_PASSWORD => $_ENV['OAUTH_USER_PASSWORD'],
    PasswordCredentials::CONFIG_CLIENT_ID => $_ENV['OAUTH_CLIENT_ID'],
    PasswordCredentials::CONFIG_CLIENT_SECRET => $_ENV['OAUTH_CLIENT_SECRET'],
    PasswordCredentials::CONFIG_TOKEN_URL => '/oauth/token',
    'scope' => $_ENV['OAUTH_SCOPE'],
];

$oauthClient = new Client(['base_uri' => $baseUri]);
$grantType = new PasswordCredentials($oauthClient, $config);
$refreshToken = new RefreshToken($oauthClient, $config);
$middleware = new OAuthMiddleware($oauthClient, $grantType, $refreshToken);

$handlerStack = HandlerStack::create();
$handlerStack->push($middleware->onBefore());
$handlerStack->push($middleware->onFailure(5));

$client = new Client(['handler'=> $handlerStack, 'base_uri' => $baseUri, 'auth' => 'oauth2']);
$response = $client->request('GET', '/api/crossbar/clients');

$decoded_response = json_decode((string) $response->getBody());

foreach ($decoded_response->data as $users) {
    foreach ($users as $username => $data) {
        $userDb[$username] = [
            'secret' => $data->key,
            'role' => $data->role
        ];
    }
}

$authenticate = function ($args) use ($userDb) {
    $realm  = array_shift($args);
    $authid = array_shift($args);
    $details = array_shift($args);

    //var_dump($realm, $authid, $details);
    echo "authenticate called: {$realm}, {$authid}, " . serialize($details) . "\n";

    if (isset($userDb[$authid])) {
        return $userDb[$authid];
    }

    echo "no such user: {$realm}, {$authid}\n";
};

$user     = $argv[3];
$password = $argv[4];

$onChallenge = function (ClientSession $session, $method, ChallengeMessage $msg) use ($user, $password) {

    if ("wampcra" !== $method) {
        return false;
    }

    $cra = new ClientWampCraAuthenticator($user, $password);
    return $cra->getAuthenticateFromChallenge($msg)->getSignature();
};

$connection = new Connection(
    [
        "realm"       => $argv[2],
        "url"         => $argv[1],
        "authmethods" => ["wampcra"],
        "onChallenge" => $onChallenge,
        "authid"      => $user
    ]
);

$connection->on('open', function (ClientSession $session) use ($connection, $authenticate) {

    echo "custom authenticator connected\n";

    $session->register('eu.hoogstraaten.authenticate', $authenticate)->then(
        function () {
            echo "Ok, custom WAMP-CRA authenticator procedure registered\n";
        },
        function ($error) {
            echo "Uups, could not register custom WAMP-CRA authenticator {$error}\n";
        }
    );
});

$connection->on('close', function ($reason) {
    echo "The authenticator client connection has closed with reason: {$reason}\n";
});

$connection->on('error', function ($reason) {
    echo "The authenticator client connection has closed with error: {$reason}\n";
});

$connection->open();

