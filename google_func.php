<?php

/**
 * Functions which can be used from plugin or cli.
 *
 * @version 1.0
 * @author Stefan L. Wagner
 */

require_once(__DIR__ . '/../../vendor/autoload.php');
require_once(__DIR__ . '/google_addressbook_backend.php');

class google_func
{
    public static $settings_key_token = 'google_current_token';
    public static $settings_key_use_plugin = 'google_use_addressbook';
    public static $settings_key_auto_sync = 'google_autosync';
    public static $settings_key_auth_code = 'google_auth_code';

    static function get_client(): \Google\Client
    {
        $config = rcmail::get_instance()->config;
        $client = new \Google\Client();
        $client->setApplicationName($config->get('google_addressbook_application_name'));
        $client->setScopes([\Google\Service\PeopleService::CONTACTS_READONLY]);
        $client->setClientId($config->get('google_addressbook_client_id'));
        $client->setClientSecret($config->get('google_addressbook_client_secret'));
        $client->setAccessType('offline');
        $client->setApprovalPrompt('force');

        if (self::has_redirect()) {
            $redirect_url = $config->get('google_addressbook_client_redirect_url');
            if ($redirect_url === null) {
                $redirect_url = 'http' . (isset($_SERVER['HTTPS']) ? 's' : '') . "://{$_SERVER['HTTP_HOST']}" . parse_url($_SERVER["REQUEST_URI"], PHP_URL_PATH) . '?_task=settings&_action=plugin.google_addressbook.auth';
            }
        } else {
            $redirect_url = 'urn:ietf:wg:oauth:2.0:oob';
        }
        $client->setRedirectUri($redirect_url);

        return $client;
    }

    static function get_service(\Google\Client $client): \Google\Service\PeopleService
    {
        return new \Google\Service\PeopleService($client);
    }

    static function has_redirect(): bool
    {
        $config = rcmail::get_instance()->config;
        return $config->get('google_addressbook_client_redirect', false);
    }

    /**
     * @return null|string
     */
    static function get_auth_code(rcube_user $user)
    {
        $prefs = $user->get_prefs();
        return $prefs[self::$settings_key_auth_code];
    }

    /**
     * @return null|array
     */
    static function get_current_token(rcube_user $user)
    {
        $prefs = $user->get_prefs();
        return $prefs[self::$settings_key_token];
    }

    static function save_current_token(rcube_user $user, array $token): bool
    {
        $prefs = [self::$settings_key_token => $token];
        $result = $user->save_prefs($prefs);
        if (!$result) {
            rcube::write_log('google_addressbook', 'Failed to save current token.');
        }
        return $result;
    }

    static function clear_authdata(rcube_user $user): bool
    {
        $prefs = [
            self::$settings_key_token => null,
            self::$settings_key_auth_code => null,
            self::$settings_key_auto_sync => false,
        ];
        $result = $user->save_prefs($prefs);
        if (!$result) {
            rcube::write_log('google_addressbook', 'Failed to clear current authdata.');
        }
        return $result;
    }

    static function is_enabled($user): bool
    {
        $prefs = $user->get_prefs();
        return isset($prefs[self::$settings_key_use_plugin]) && $prefs[self::$settings_key_use_plugin];
    }

    static function is_autosync($user): bool
    {
        $prefs = $user->get_prefs();
        return (bool)$prefs[self::$settings_key_auto_sync];
    }

    static function google_authenticate(\Google\Client $client, rcube_user $user): array
    {
        $rcmail = rcmail::get_instance();
        $token = self::get_current_token($user);
        if ($token !== null) {
            $client->setAccessToken($token);
        }

        $success = false;

        try {
            $token = $client->getAccessToken();
            if (empty($token)) {
                $code = self::get_auth_code($user);
                if (empty($code)) {
                    throw new Exception($rcmail->gettext('noauthcode', 'google_addressbook'));
                }
                $client->fetchAccessTokenWithAuthCode($code);
                $msg = $rcmail->gettext('done', 'google_addressbook');
                $success = true;
            } else {
                if ($client->isAccessTokenExpired()) {
                    if (empty($token['refresh_token'])) {
                        throw new Exception("Error fetching refresh token.");
                        // this only happens if google client id is wrong and access type != offline
                    } else {
                        $client->refreshToken($token['refresh_token']);
                        $msg = $rcmail->gettext('done', 'google_addressbook');
                        $success = true;
                    }
                } else {
                    // token valid, nothing to do.
                    $msg = $rcmail->gettext('done', 'google_addressbook');
                    $success = true;
                }
            }
        } catch (Exception $e) {
            $msg = $e->getMessage();
            // invalidate saved authdata as they are probably invalid
            if (strpos($msg, "'invalid_grant: Bad Request'") !== false) {
                self::clear_authdata($user);
            }
            error_log('google_addressbook: ' . $msg);
            rcube::write_log('google_addressbook', $msg);
        }

        if ($success) {
            $token = $client->getAccessToken();
            self::save_current_token($user, $token);
        }

        return ['success' => $success, 'message' => $msg];
    }

    static function google_sync_contacts(rcube_user $user): array
    {
        $rcmail = rcmail::get_instance();
        $client = self::get_client();

        $auth_res = self::google_authenticate($client, $user);
        if (!$auth_res['success']) {
            return $auth_res;
        }

        $service = self::get_service($client);

        $optParams = [
            'personFields' => 'names,emailAddresses,phoneNumbers,photos',
            'pageSize' => 100,
        ];

        $persons = [];
        try {
            $nextPageToken = -1;
            while (!empty($nextPageToken)) {
                if ($nextPageToken !== -1) {
                    $optParams['pageToken'] = $nextPageToken;
                }
                $response = $service->people_connections->listPeopleConnections('people/me', $optParams);
                $nextPageToken = $response->getNextPageToken();
                $connections = $response->getConnections();
                $persons = array_merge($persons, $connections);
            }
        } catch (\Google\Service\Exception $e) { // can be thrown even though IDE says otherwise
            $message = json_decode($e->getMessage());
            $error = trim($message->error_description, '.');
            switch ($e->getCode()) {
                case 401:
                    return ['success' => false, 'message' => $rcmail->gettext('googleauthfailed', 'google_addressbook')];
                case 403:
                    return ['success' => false, 'message' => $rcmail->gettext('googleforbidden', 'google_addressbook')];
                default:
                    return [
                        'success' => false,
                        'message' => $rcmail->gettext(
                            ['name' => 'googleunreachable', 'vars' => ['error' => $error]],
                            'google_addressbook'
                        )
                    ];
            }
        }

        $backend = new google_addressbook_backend($rcmail->get_dbh(), $user->ID);
        $backend->delete_all();

        if (empty($persons)) {
            // When the user does not have any google contacts. Avoids PHP Warning in foreach.
            return ['success' => true, 'message' => '0' . $rcmail->gettext('contactsfound', 'google_addressbook')];
        }

        $num_entries = 0;
        foreach ($persons as $person) {
            $record = [];
            $name = reset($person->names);
            //write_log('google_addressbook', 'getting contact: ' . $name->displayName);
            $record['name'] = trim($name->displayName ?? '');
            $record['firstname'] = trim($name->givenName ?? '');
            $record['surname'] = trim($name->familyName ?? '');
            $record['middlename'] = trim($name->middleName ?? '');
            $record['prefix'] = $name->honorificPrefix ?? '';
            $record['suffix'] = $name->honorificSuffix ?? '';

            if (!empty($person->emailAddresses)) {
                foreach ($person->emailAddresses as $email) {
                    $type = empty($email['type']) ? '' : ':' . $email['type'];
                    if (!isset($record['email' . $type])) {
                        $record['email' . $type] = [];
                    }
                    $record['email' . $type][] = $email['value'];
                }
            }

            if (!empty($person->phoneNumbers)) {
                foreach ($person->phoneNumbers as $phone) {
                    $type = empty($phone['type']) ? '' : ':' . $phone['type'];
                    if (!isset($record['phone' . $type])) {
                        $record['phone' . $type] = [];
                    }
                    $record['phone' . $type][] = $phone['value'];
                }
            }

            if (!empty($person->photos)) {
                $photo = reset($person->photos);
                $photo_client = new \GuzzleHttp\Client();
                try {
                    $response = $photo_client->request('GET', $photo['url']);
                } catch (\GuzzleHttp\Exception\GuzzleException $e) {
                }
                if (isset($response) && ($response->getStatusCode() == 200)) {
                    $record['photo'] = $response->getBody()->getContents();
                }
            }

            $num_entries++;

            $backend->insert($record);
        }

        return ['success' => true, 'message' => $num_entries . $rcmail->gettext('contactsfound', 'google_addressbook')];
    }
}
