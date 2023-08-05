<?php

/**
 * Google Addressbook
 *
 * Plugin to use google contacts in roundcube mail.
 *
 * @version 1.0
 * @author Stefan L. Wagner
 * @url https://github.com/stwa/google-addressbook
 */

require_once(__DIR__ . '/google_addressbook_backend.php');
require_once(__DIR__ . '/google_addressbook_functions.php');

class google_addressbook extends rcube_plugin
{
    public $task = 'mail|addressbook|settings';
    private $abook_id = 'google_addressbook';
    private $abook_name = 'Google Addressbook';

    function init()
    {
        $rcmail = rcmail::get_instance();

        $this->add_texts('localization/', true);

        // register actions
        $this->register_action('plugin.google_addressbook.auth', [$this, 'handle_auth_requests']);
        $this->register_action('plugin.google_addressbook.sync', [$this, 'handle_sync_requests']);

        // register hooks
        $this->add_hook('preferences_list', [$this, 'preferences_list']);
        $this->add_hook('preferences_save', [$this, 'preferences_save']);
        $this->add_hook('addressbooks_list', [$this, 'addressbooks_list']);
        $this->add_hook('addressbook_get', [$this, 'addressbook_get']);
        $this->add_hook('contact_create', [$this, 'contact_create']);
        $this->add_hook('contact_update', [$this, 'contact_update']);
        $this->add_hook('contact_delete', [$this, 'contact_delete']);

        // add google addressbook to autocomplete addressbooks
        $sources = (array)$rcmail->config->get('autocomplete_addressbooks', 'sql');
        $sources[] = $this->abook_id;
        $rcmail->config->set('autocomplete_addressbooks', $sources);

        $this->include_script('google_addressbook.js');

        // only call command when in ajax action 'list'
        if ($rcmail->output->type == 'js' && $rcmail->action == 'list') {
            if ($this->is_enabled() && $this->is_autosync() && !isset($_SESSION['google_addressbook_synced'])) {
                $rcmail->output->command('plugin.google_addressbook.autosync', ['message' => $this->gettext('done')]);
            }
        }
    }

    /**
     * @return null|array
     */
    function get_current_token()
    {
        return google_addressbook_functions::get_current_token(rcmail::get_instance()->user);
    }

    function save_current_token($token): bool
    {
        return google_addressbook_functions::save_current_token(rcmail::get_instance()->user, $token);
    }

    function is_enabled(): bool
    {
        return google_addressbook_functions::is_enabled(rcmail::get_instance()->user);
    }

    function is_autosync(): bool
    {
        return google_addressbook_functions::is_autosync(rcmail::get_instance()->user);
    }

    function handle_auth_requests()
    {
        $rcmail = rcmail::get_instance();
        if (isset($_GET['error'])) {
            $rcmail->output->show_message(htmlspecialchars($_GET['error']), 'error');
            return;
        }
        $auth_code = $_GET['code'];
        $user = $rcmail->user;
        $prefs = [google_addressbook_functions::SETTINGS_KEY_AUTH_CODE => $auth_code, google_addressbook_functions::SETTINGS_KEY_TOKEN => null];
        if (!$user->save_prefs($prefs)) {
            rcmail_action::display_server_error('errorsaving');
            return;
        }
        $client = google_addressbook_functions::get_client();
        $res = google_addressbook_functions::google_authenticate($client, $user);
        $rcmail->output->show_message($res['message'], $res['success'] ? 'confirmation' : 'error');
    }

    function handle_sync_requests()
    {
        $this->sync_contacts();
        rcmail::get_instance()->output->command('plugin.google_addressbook.finished', ['message' => $this->gettext('done')]);
    }

    function preferences_list(array $params): array
    {
        $rcmail = rcmail::get_instance();

        if ($params['section'] == 'addressbook') {
            $params['blocks'][$this->ID]['name'] = $this->abook_name;

            $field_id = 'rc_use_plugin';
            $checkbox = new html_checkbox(['name' => $field_id, 'id' => $field_id, 'value' => 1]);
            $params['blocks'][$this->ID]['options'][$field_id] = [
                'title' => html::label($field_id, $this->gettext('use') . $this->abook_name),
                'content' => $checkbox->show($rcmail->config->get(google_addressbook_functions::SETTINGS_KEY_USE_PLUGIN))
            ];

            $field_id = 'rc_google_autosync';
            $checkbox = new html_checkbox(['name' => $field_id, 'id' => $field_id, 'value' => 1]);
            $params['blocks'][$this->ID]['options'][$field_id] = [
                'title' => html::label($field_id, $this->gettext('autosync')),
                'content' => $checkbox->show($rcmail->config->get(google_addressbook_functions::SETTINGS_KEY_AUTO_SYNC))
            ];

            if (!google_addressbook_functions::get_client()->getClientId() || !google_addressbook_functions::get_client()->getClientSecret()) {
                $params['blocks'][$this->ID]['options']['rc_google_error'] = [
                    'title' => '',
                    'content' => html::label('rc_google_error', $this->gettext('invalidconfiguration'))
                ];
            } else {
                $auth_link = ['target' => '_top'];
                if (!google_addressbook_functions::has_redirect()) {
                    $field_id = 'rc_google_authcode';
                    $input_auth = new html_inputfield(['name' => $field_id, 'id' => $field_id, 'size' => 45]);
                    $params['blocks'][$this->ID]['options'][$field_id] = [
                        'title' => html::label($field_id, $this->gettext('authcode')),
                        'content' => $input_auth->show($rcmail->config->get(google_addressbook_functions::SETTINGS_KEY_AUTH_CODE))
                    ];
                    $auth_link['target'] = '_blank';
                }
                $auth_link['href'] = google_addressbook_functions::get_client()->createAuthUrl();
                $params['blocks'][$this->ID]['options']['link'] = [
                    'title' => html::span('', ''),
                    'content' => html::a($auth_link, $this->gettext('authcodelink'))
                ];
            }
        }
        return $params;
    }

    function preferences_save(array $params): array
    {
        if ($params['section'] == 'addressbook') {
            if (!google_addressbook_functions::has_redirect()) {
                $old_prefs = rcmail::get_instance()->user->get_prefs();
                $new_code = rcube_utils::get_input_value('rc_google_authcode', rcube_utils::INPUT_POST);
                if ($old_prefs[google_addressbook_functions::SETTINGS_KEY_AUTH_CODE] != $new_code) {
                    // token is no longer valid, so delete it
                    $this->save_current_token(null);
                }
                $params['prefs'][google_addressbook_functions::SETTINGS_KEY_AUTH_CODE] = $new_code;
            }
            $params['prefs'][google_addressbook_functions::SETTINGS_KEY_USE_PLUGIN] = isset($_POST['rc_use_plugin']);
            $params['prefs'][google_addressbook_functions::SETTINGS_KEY_AUTO_SYNC] = isset($_POST['rc_google_autosync']);
        }
        return $params;
    }

    // roundcube collects information about available addressbooks
    function addressbooks_list(array $params): array
    {
        if ($this->is_enabled()) {
            $params['sources'][] = [
                'id' => $this->abook_id,
                'name' => $this->abook_name,
                'groups' => false,
                'readonly' => true,
                'autocomplete' => true
            ];
        }
        return $params;
    }

    // user opens addressbook
    function addressbook_get(array $params): array
    {
        $rcmail = rcmail::get_instance();
        if ($params['id'] == $this->abook_id) {
            $params['instance'] = new google_addressbook_backend($rcmail->get_dbh(), $rcmail->user->ID);
            $params['writable'] = false;
        }

        return $params;
    }

    function sync_contacts()
    {
        $rcmail = rcmail::get_instance();

        $_SESSION['google_addressbook_synced'] = true;

        $res = google_addressbook_functions::google_sync_contacts($rcmail->user);
        $rcmail->output->show_message($res['message'], $res['success'] ? 'confirmation' : 'error');
    }

    function contact_create($params)
    {
        rcube::write_log(google_addressbook_functions::LOG_IDENT, 'contact_create: uid:' . rcmail::get_instance()->user->ID . ' ' . json_encode($params, JSON_UNESCAPED_UNICODE + JSON_UNESCAPED_SLASHES));
        // TODO: not supported right now
    }

    function contact_update($params)
    {
        rcube::write_log(google_addressbook_functions::LOG_IDENT, 'contact_update: uid:' . rcmail::get_instance()->user->ID . ' ' . json_encode($params, JSON_UNESCAPED_UNICODE + JSON_UNESCAPED_SLASHES));
        // TODO: not supported right now
    }

    function contact_delete($params)
    {
        rcube::write_log(google_addressbook_functions::LOG_IDENT, 'contact_delete: uid:' . rcmail::get_instance()->user->ID . ' ' . json_encode($params, JSON_UNESCAPED_UNICODE + JSON_UNESCAPED_SLASHES));
        // TODO: not supported right now
    }
}
