/**
 * Javascript events and handlers
 *
 * @version 1.0
 * @author Stefan L. Wagner
 */

function is_addressbook_view() {
	if (rcmail.env.address_sources) {
		for (let key in rcmail.env.address_sources) {
			if (rcmail.env.address_sources[key].id === 'google_addressbook') {
				return true;
			}
		}
	}
	return false;
}

function sync_handler() {
	let lock = rcmail.set_busy(true, 'sync');
	rcmail.http_post('plugin.google_addressbook.sync', '', lock);
}

function sync_finished(response) {
	if (is_addressbook_view()) {
		rcmail.command('list', 'google_addressbook');
	}
}

if (window.rcmail) {
	rcmail.addEventListener('init', function (evt) {

		rcmail.addEventListener('plugin.google_addressbook.autosync', sync_handler);
		rcmail.addEventListener('plugin.google_addressbook.finished', sync_finished);

		if (is_addressbook_view()) {
			let button = $('<a>').attr('id', 'rcmbtnsyncgoogle').attr('href', 'javascript:');
			button.addClass('button checkmail').html(rcmail.gettext('sync', 'google_addressbook'));
			button.bind('click', function (e) {
				return rcmail.command('plugin.google_addressbook.sync', this);
			});

			rcmail.add_element(button, 'toolbar');
			rcmail.register_button('plugin.google_addressbook.sync', 'rcmbtnsyncgoogle', 'link');
			rcmail.register_command('plugin.google_addressbook.sync', sync_handler, true);
		}
	});

}
