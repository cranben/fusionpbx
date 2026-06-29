<?php
/*
	FusionPBX
	Version: MPL 1.1

	The contents of this file are subject to the Mozilla Public License Version
	1.1 (the "License"); you may not use this file except in compliance with
	the License. You may obtain a copy of the License at
	http://www.mozilla.org/MPL/

	Software distributed under the License is distributed on an "AS IS" basis,
	WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
	for the specific language governing rights and limitations under the
	License.
*/

//includes files
	require_once dirname(__DIR__, 2) . "/resources/require.php";
	require_once "resources/check_auth.php";
	require_once dirname(__DIR__, 2) . "/app/diagnostics/resources/classes/diagnostic_collector.php";
	require_once dirname(__DIR__, 2) . "/app/diagnostics/resources/classes/diagnostic_bundle.php";

//check permissions
	if (!permission_exists('diagnostics_collect')) {
		echo "access denied";
		exit;
	}

//add multi-lingual support
	$language = new text;
	$text = $language->get();

//prepare the collector
	$collector = new diagnostic_collector;

//initialize detailed CDR preview state
	$cdr_match_preview = null;
	$cdr_preview_records = [];
	$cdr_filters = [
		'start_datetime' => '',
		'end_datetime' => '',
		'destination_number' => '',
		'caller_id' => '',
		'extension' => '',
		'call_uuid' => '',
		'max_records' => 25,
		'include_logs' => false,
		'scope' => 'current_domain',
	];

//download the diagnostic bundle
	if (isset($_POST['action']) && $_POST['action'] === 'download_bundle') {
		if (!permission_exists('diagnostics_download')) {
			echo "access denied";
			exit;
		}

		$token = new token;
		if (!$token->validate($_SERVER['PHP_SELF'])) {
			message::add($text['message-invalid_token'], 'negative');
			header('Location: diagnostic_collect.php');
			exit;
		}

		try {
			$sections = $collector->collect_sections();
			$metadata = [
				'schema_version' => diagnostic_collector::SCHEMA_VERSION,
				'collector_version' => diagnostic_collector::COLLECTOR_VERSION,
				'generated_at' => gmdate('c'),
				'options' => [],
			];
			$bundle = new diagnostic_bundle;
			$bundle->stream($metadata, $sections);
		}
		catch (Throwable $e) {
			message::add($e->getMessage(), 'negative');
			header('Location: diagnostic_collect.php');
			exit;
		}
	}

//preview detailed CDR match count
	if (isset($_POST['action']) && $_POST['action'] === 'preview_cdr_match_count') {
		$token = new token;
		if (!$token->validate($_SERVER['PHP_SELF'])) {
			message::add($text['message-invalid_token'], 'negative');
			header('Location: diagnostic_collect.php');
			exit;
		}

		$cdr_filters = [
			'start_datetime' => trim((string) ($_POST['cdr_start_datetime'] ?? '')),
			'end_datetime' => trim((string) ($_POST['cdr_end_datetime'] ?? '')),
			'destination_number' => trim((string) ($_POST['cdr_destination_number'] ?? '')),
			'caller_id' => trim((string) ($_POST['cdr_caller_id'] ?? '')),
			'extension' => trim((string) ($_POST['cdr_extension'] ?? '')),
			'call_uuid' => trim((string) ($_POST['cdr_call_uuid'] ?? '')),
			'max_records' => $_POST['cdr_max_records'] ?? 25,
			'include_logs' => !empty($_POST['cdr_include_logs']),
			'scope' => trim((string) ($_POST['cdr_scope'] ?? 'current_domain')),
		];

		$cdr_match_preview = $collector->collect_cdr_detailed_match_count($cdr_filters);
		if (empty($cdr_match_preview['errors'])) {
			$cdr_preview_response = $collector->collect_cdr_preview_records($cdr_filters);
			$cdr_preview_records = is_array($cdr_preview_response['records'] ?? null) ? $cdr_preview_response['records'] : [];
			if (!empty($cdr_preview_response['errors'])) {
				$cdr_match_preview['errors'] = array_values(array_unique(array_merge(
					is_array($cdr_match_preview['errors'] ?? null) ? $cdr_match_preview['errors'] : [],
					is_array($cdr_preview_response['errors'] ?? null) ? $cdr_preview_response['errors'] : []
				)));
			}
		}
	}


//download bounded selected-call CDR evidence bundle
	if (isset($_POST['action']) && $_POST['action'] === 'download_cdr_evidence_bundle') {
		if (!permission_exists('diagnostics_collect') || !permission_exists('diagnostics_download') || !permission_exists('xml_cdr_view')) {
			echo "access denied";
			exit;
		}

		$token = new token;
		if (!$token->validate($_SERVER['PHP_SELF'])) {
			message::add($text['message-invalid_token'], 'negative');
			header('Location: diagnostic_collect.php');
			exit;
		}

		$cdr_filters = [
			'start_datetime' => trim((string) ($_POST['cdr_start_datetime'] ?? '')),
			'end_datetime' => trim((string) ($_POST['cdr_end_datetime'] ?? '')),
			'destination_number' => trim((string) ($_POST['cdr_destination_number'] ?? '')),
			'caller_id' => trim((string) ($_POST['cdr_caller_id'] ?? '')),
			'extension' => trim((string) ($_POST['cdr_extension'] ?? '')),
			'call_uuid' => trim((string) ($_POST['cdr_call_uuid'] ?? '')),
			'max_records' => $_POST['cdr_max_records'] ?? 25,
			'include_logs' => !empty($_POST['cdr_include_logs']),
			'scope' => trim((string) ($_POST['cdr_scope'] ?? 'current_domain')),
		];

		try {
			$cdr_evidence_sections = $collector->collect_cdr_selected_evidence_sections($cdr_filters, [
				'prior_preview_matched_count' => $_POST['cdr_preview_matched_count'] ?? null,
				'prior_preview_selected_count' => $_POST['cdr_preview_selected_count'] ?? null,
			]);

			if (!empty($cdr_evidence_sections['errors'])) {
				foreach ((array) $cdr_evidence_sections['errors'] as $error_message) {
					$error_message = trim((string) $error_message);
					if ($error_message !== '') {
						message::add($error_message, 'negative');
					}
				}
				header('Location: diagnostic_collect.php');
				exit;
			}

			$sections = $collector->collect_sections();
			$sections['cdr_collection_policy'] = $cdr_evidence_sections['collection_policy'] ?? [];
			$sections['cdr_selected_call_index'] = $cdr_evidence_sections['call_index'] ?? [];
			$sections['cdr_selected_calls'] = $cdr_evidence_sections['selected_calls'] ?? [];

			$metadata = [
				'schema_version' => diagnostic_collector::SCHEMA_VERSION,
				'collector_version' => diagnostic_collector::COLLECTOR_VERSION,
				'generated_at' => gmdate('c'),
				'options' => [
					'bundle_type' => 'cdr_evidence_phase_1a',
				],
				'warnings' => $cdr_evidence_sections['warnings'] ?? [],
			];
			$bundle = new diagnostic_bundle;
			$bundle->stream($metadata, $sections);
		}
		catch (Throwable $e) {
			message::add($e->getMessage(), 'negative');
			header('Location: diagnostic_collect.php');
			exit;
		}
	}

	$show_cdr_details = is_array($cdr_match_preview);
	$cdr_match_count_errors = [];
	if (is_array($cdr_match_preview) && is_array($cdr_match_preview['errors'] ?? null)) {
		foreach ($cdr_match_preview['errors'] as $cdr_error) {
			$cdr_error = trim((string) $cdr_error);
			if ($cdr_error !== '') {
				$cdr_match_count_errors[] = $cdr_error;
			}
		}
	}
	$cdr_preview_records = is_array($cdr_preview_records) ? $cdr_preview_records : [];

//collect diagnostic section objects
	$sections = $collector->collect_sections();
	$system_preview = $sections['system'] ?? [];
	$domains_preview = $sections['domains'] ?? [];
	$extensions_preview = $sections['extensions'] ?? [];
	$gateways_preview = $sections['gateways'] ?? [];
	$access_controls_preview = $sections['access_controls'] ?? [];
	$dialplans_preview = $sections['dialplans'] ?? [];
	$destinations_preview = $sections['destinations'] ?? [];
	$sip_profiles_preview = $sections['sip_profiles'] ?? [];
	$variables_preview = $sections['variables'] ?? [];
	$registrations_preview = $sections['registrations'] ?? [];
	$sip_status_preview = $sections['sip_status'] ?? [];

//set the collector sections
	$current_sections = [
		[
			'name' => 'System Information Preview',
			'status' => $system_preview['status'] ?? 'collected',
			'scope' => 'current session',
			'record_count' => '1',
			'details_type' => 'system',
			'details' => $system_preview,
		],
	];
	$planned_configuration_sections = [
	];
	$domains_section = [
		'name' => 'Domains Preview',
		'status' => $domains_preview['status'] ?? 'planned',
		'scope' => $domains_preview['scope'] ?? 'current domain',
		'record_count' => $domains_preview['record_count'] ?? '-',
		'details_type' => 'domains',
		'details' => $domains_preview,
	];
	if (($domains_preview['status'] ?? '') === 'collected') {
		$current_sections[] = $domains_section;
	}
	else {
		array_unshift($planned_configuration_sections, $domains_section);
	}
	$extensions_section = [
		'name' => 'Extensions Preview',
		'status' => $extensions_preview['status'] ?? 'planned',
		'scope' => $extensions_preview['scope'] ?? 'current domain',
		'record_count' => $extensions_preview['record_count'] ?? '-',
		'details_type' => 'extensions',
		'details' => $extensions_preview,
	];
	if (($extensions_preview['status'] ?? '') === 'collected') {
		$current_sections[] = $extensions_section;
	}
	else {
		array_unshift($planned_configuration_sections, $extensions_section);
	}
	$gateways_section = [
		'name' => 'Gateways Preview',
		'status' => $gateways_preview['status'] ?? 'planned',
		'scope' => $gateways_preview['scope'] ?? 'current domain',
		'record_count' => $gateways_preview['record_count'] ?? '-',
		'details_type' => 'gateways',
		'details' => $gateways_preview,
	];
	if (($gateways_preview['status'] ?? '') === 'collected') {
		$current_sections[] = $gateways_section;
	}
	else {
		array_unshift($planned_configuration_sections, $gateways_section);
	}
	$access_controls_section = [
		'name' => 'ACLs Preview',
		'status' => $access_controls_preview['status'] ?? 'planned',
		'scope' => $access_controls_preview['scope'] ?? 'global',
		'record_count' => $access_controls_preview['record_count'] ?? '-',
		'details_type' => 'access_controls',
		'details' => $access_controls_preview,
	];
	if (($access_controls_preview['status'] ?? '') === 'collected') {
		$current_sections[] = $access_controls_section;
	}
	else {
		array_unshift($planned_configuration_sections, $access_controls_section);
	}

	$dialplans_section = [
		'name' => 'Dialplans Preview',
		'status' => $dialplans_preview['status'] ?? 'planned',
		'scope' => $dialplans_preview['scope'] ?? 'current domain/global',
		'record_count' => $dialplans_preview['record_count'] ?? '-',
		'details_type' => 'dialplans',
		'details' => $dialplans_preview,
	];
	if (($dialplans_preview['status'] ?? '') === 'collected') {
		$current_sections[] = $dialplans_section;
	}
	else {
		array_unshift($planned_configuration_sections, $dialplans_section);
	}

	$destinations_section = [
		'name' => 'Destinations Preview',
		'status' => $destinations_preview['status'] ?? 'planned',
		'scope' => $destinations_preview['scope'] ?? 'current domain',
		'record_count' => $destinations_preview['record_count'] ?? '-',
		'details_type' => 'destinations',
		'details' => $destinations_preview,
	];
	if (($destinations_preview['status'] ?? '') === 'collected') {
		$current_sections[] = $destinations_section;
	}
	else {
		array_unshift($planned_configuration_sections, $destinations_section);
	}

	$sip_profiles_section = [
		'name' => 'SIP Profiles Preview',
		'status' => $sip_profiles_preview['status'] ?? 'planned',
		'scope' => $sip_profiles_preview['scope'] ?? 'global',
		'record_count' => $sip_profiles_preview['record_count'] ?? '-',
		'details_type' => 'sip_profiles',
		'details' => $sip_profiles_preview,
	];
	if (($sip_profiles_preview['status'] ?? '') === 'collected') {
		$current_sections[] = $sip_profiles_section;
	}
	else {
		array_unshift($planned_configuration_sections, $sip_profiles_section);
	}

	$variables_section = [
		'name' => 'Variables Preview',
		'status' => $variables_preview['status'] ?? 'planned',
		'scope' => $variables_preview['scope'] ?? 'global',
		'record_count' => $variables_preview['record_count'] ?? '-',
		'details_type' => 'variables',
		'details' => $variables_preview,
	];
	if (($variables_preview['status'] ?? '') === 'collected') {
		$current_sections[] = $variables_section;
	}
	else {
		array_unshift($planned_configuration_sections, $variables_section);
	}
	$planned_runtime_sections = [
	];
	$sip_status_section = [
		'name' => 'SIP Status Preview',
		'status' => $sip_status_preview['status'] ?? 'planned',
		'scope' => $sip_status_preview['scope'] ?? 'global',
		'record_count' => $sip_status_preview['record_count'] ?? '-',
		'details_type' => 'sip_status',
		'details' => $sip_status_preview,
	];
	if (($sip_status_preview['status'] ?? '') === 'collected') {
		$current_sections[] = $sip_status_section;
	}
	else {
		$planned_runtime_sections[] = $sip_status_section;
	}

	$registrations_section = [
		'name' => 'Registrations Preview',
		'status' => $registrations_preview['status'] ?? 'planned',
		'scope' => $registrations_preview['scope'] ?? 'current domain',
		'record_count' => $registrations_preview['record_count'] ?? '-',
		'details_type' => 'registrations',
		'details' => $registrations_preview,
	];
	if (($registrations_preview['status'] ?? '') === 'collected') {
		$current_sections[] = $registrations_section;
	}
	else {
		array_unshift($planned_runtime_sections, $registrations_section);
	}

	$section_groups = [
		[
			'name' => 'Current',
			'sections' => $current_sections,
		],
		[
			'name' => 'Planned Configuration Sources',
			'sections' => $planned_configuration_sections,
		],
		[
			'name' => 'Planned Runtime Sources',
			'sections' => $planned_runtime_sections,
		],
		[
			'name' => 'Planned Optional Sources',
			'sections' => [
				['name' => 'CDR Summary', 'status' => 'planned', 'scope' => 'bounded range', 'record_count' => '-'],
				['name' => 'CDR Export', 'status' => 'skipped', 'scope' => 'optional', 'record_count' => '-'],
			],
		],
	];

//create token
	$object = new token;
	$token = $object->create($_SERVER['PHP_SELF']);

//set current domain display for optional detailed CDR UI
	$current_domain_display = $_SESSION['domain_name'] ?? '';
	if (!empty($_SESSION['domain_uuid'])) {
		$current_domain_display .= (!empty($current_domain_display) ? ' ' : null).'('.$_SESSION['domain_uuid'].')';
	}

//include the header
	$document['title'] = $text['title-diagnostic_collect'];
	require_once "resources/header.php";

//show the content
	echo "<div class='action_bar' id='action_bar'>\n";
	echo "	<div class='heading'><b>".$text['header-diagnostic_collect']."</b></div>\n";
	echo "	<div class='actions'>\n";
	if (permission_exists('diagnostics_download')) {
		echo "		<form method='post' class='inline'>\n";
		echo "		<input type='hidden' name='action' value='download_bundle'>\n";
		echo "		<input type='hidden' name='".$token['name']."' value='".$token['hash']."'>\n";
		echo button::create(['type'=>'submit','label'=>'Download Bundle','icon'=>$settings->get('theme', 'button_icon_download')]);
		echo "		</form>\n";
	}
	if (permission_exists('diagnostics_view')) {
		echo button::create(['type'=>'button','label'=>$text['button-back'],'icon'=>$settings->get('theme', 'button_icon_back'),'link'=>'diagnostics.php']);
	}
	echo "	</div>\n";
	echo "	<div style='clear: both;'></div>\n";
	echo "</div>\n";

	echo $text['description-diagnostic_collect']."\n";
	echo "<br /><br />\n";

	echo "<style>\n";
	echo "	.diagnostics-toggle { cursor: pointer; user-select: none; }\n";
	echo "	.diagnostics-caret { display: inline-block; width: 1.25em; }\n";
	echo "	.diagnostics-child { padding-left: 2.25em; }\n";
	echo "	.diagnostics-details { display: none; }\n";
	echo "	.diagnostics-detail-table td:first-child { width: 220px; font-weight: 600; }\n";
	echo "	.diagnostics-hash { font-family: monospace; font-size: 90%; overflow-wrap: anywhere; }\n";
	echo "	.diagnostics-raw-json { white-space: pre-wrap; overflow-wrap: anywhere; margin: 0; font-family: monospace; font-size: 90%; }\n";
	echo "</style>\n";
	echo "<script>\n";
	echo "	function diagnostics_toggle(id) {\n";
	echo "		var row = document.getElementById(id);\n";
	echo "		var caret = document.getElementById(id + '_caret');\n";
	echo "		if (!row) { return; }\n";
	echo "		if (row.style.display === 'none' || row.style.display === '') {\n";
	echo "			row.style.display = 'table-row';\n";
	echo "			if (caret) { caret.innerHTML = '&#9662;'; }\n";
	echo "		}\n";
	echo "		else {\n";
	echo "			row.style.display = 'none';\n";
	echo "			if (caret) { caret.innerHTML = '&#9656;'; }\n";
	echo "		}\n";
	echo "	}\n";
	echo "	function diagnostics_reset_cdr_form() {\n";
	echo "		var form = document.getElementById('diagnostics_cdr_preview_form');\n";
	echo "		if (!form) { return false; }\n";
	echo "		var fields = ['cdr_start_datetime','cdr_end_datetime','cdr_destination_number','cdr_caller_id','cdr_extension','cdr_call_uuid'];\n";
	echo "		for (var i = 0; i < fields.length; i++) { if (form[fields[i]]) { form[fields[i]].value = ''; } }\n";
	echo "		if (form.cdr_max_records) { form.cdr_max_records.value = '25'; }\n";
	echo "		if (form.cdr_include_logs) { form.cdr_include_logs.checked = false; }\n";
	echo "		if (form.cdr_scope) { form.cdr_scope.value = 'current_domain'; }\n";
	echo "		return false;\n";
	echo "	}\n";
	echo "</script>\n";

	echo "<div class='card'>\n";
	echo "<table class='list'>\n";
	echo "<tr class='list-row diagnostics-toggle' onclick=\"diagnostics_toggle('diagnostics_cdr_details')\">\n";
	echo "	<td><span class='diagnostics-caret' id='diagnostics_cdr_details_caret'>".($show_cdr_details ? '&#9662;' : '&#9656;')."</span><b>Detailed CDR Collection</b></td>\n";
	echo "	<td>optional / request-driven</td>\n";
	echo "</tr>\n";
	echo "<tr class='list-row diagnostics-details' id='diagnostics_cdr_details'".($show_cdr_details ? " style='display: table-row;'" : '').">\n";
	echo "	<td colspan='2'>\n";
	echo "		<div class='diagnostics-child'>\n";
	echo "			Detailed CDR collection is optional and request-driven because raw call evidence can be database intensive. Required: either Call UUID, or Start Datetime plus End Datetime. Other filters are optional. This Phase 1A panel supports bounded selected-call evidence metadata export. It does not include raw CDR bodies, transcript bodies, recording audio, or analysis findings.\n";
	echo "			<br /><br />\n";
	echo "			<form id='diagnostics_cdr_preview_form' method='post'>\n";
	echo "			<table class='list diagnostics-detail-table'>\n";
	echo "			<tr class='list-row'>\n";
	echo "				<td>Current Domain</td>\n";
	echo "				<td><input type='text' class='txt' name='cdr_domain_display' value=\"".escape($current_domain_display)."\" readonly='readonly'></td>\n";
	echo "			</tr>\n";
	echo "			<tr class='list-row'>\n";
	echo "				<td>Scope</td>\n";
	echo "				<td><select class='select' name='cdr_scope'>";
	echo "<option value='current_domain'".((($cdr_filters['scope'] ?? 'current_domain') !== 'all_domains') ? " selected='selected'" : '').">Current domain</option>";
	if (permission_exists('xml_cdr_all')) {
		echo "<option value='all_domains'".((($cdr_filters['scope'] ?? '') === 'all_domains') ? " selected='selected'" : '').">All domains</option>";
	}
	echo "</select></td>\n";
	echo "			</tr>\n";
	echo "			<tr class='list-row'>\n";
	echo "				<td>Start Datetime</td>\n";
	echo "				<td><input type='datetime-local' class='txt' name='cdr_start_datetime' value=\"".escape($cdr_filters['start_datetime'] ?? '')."\"></td>\n";
	echo "			</tr>\n";
	echo "			<tr class='list-row'>\n";
	echo "				<td>End Datetime</td>\n";
	echo "				<td><input type='datetime-local' class='txt' name='cdr_end_datetime' value=\"".escape($cdr_filters['end_datetime'] ?? '')."\"></td>\n";
	echo "			</tr>\n";
	echo "			<tr class='list-row'>\n";
	echo "				<td>Destination / DID contains</td>\n";
	echo "				<td><input type='text' class='txt' name='cdr_destination_number' value=\"".escape($cdr_filters['destination_number'] ?? '')."\"></td>\n";
	echo "			</tr>\n";
	echo "			<tr class='list-row'>\n";
	echo "				<td>Caller ID number/name contains</td>\n";
	echo "				<td><input type='text' class='txt' name='cdr_caller_id' value=\"".escape($cdr_filters['caller_id'] ?? '')."\"></td>\n";
	echo "			</tr>\n";
	echo "			<tr class='list-row'>\n";
	echo "				<td>Extension</td>\n";
	echo "				<td><input type='text' class='txt' name='cdr_extension' value=\"".escape($cdr_filters['extension'] ?? '')."\"></td>\n";
	echo "			</tr>\n";
	echo "			<tr class='list-row'>\n";
	echo "				<td>Call UUID</td>\n";
	echo "				<td><input type='text' class='txt' name='cdr_call_uuid' value=\"".escape($cdr_filters['call_uuid'] ?? '')."\"></td>\n";
	echo "			</tr>\n";
	echo "			<tr class='list-row'>\n";
	echo "				<td>Max Records</td>\n";
	echo "				<td><input type='number' class='txt' name='cdr_max_records' value=\"".escape((string) ($cdr_filters['max_records'] ?? 25))."\" min='1' max='100' step='1'></td>\n";
	echo "			</tr>\n";
	echo "			<tr class='list-row'>\n";
	echo "				<td>Include Logs</td>\n";
	echo "				<td><input type='checkbox' name='cdr_include_logs' value='true'".(!empty($cdr_filters['include_logs']) ? " checked='checked'" : '')."></td>\n";
	echo "			</tr>\n";
	echo "			<tr class='list-row'>\n";
	echo "				<td>&nbsp;</td>\n";
	echo "				<td>\n";
	echo "					<input type='hidden' id='cdr_form_action' name='action' value='preview_cdr_match_count'>\n";
	echo "					<input type='hidden' name='".$token['name']."' value='".$token['hash']."'>\n";
	echo 	button::create(['type'=>'submit','label'=>'Submit','icon'=>'search']);
	echo button::create([
		'type' => 'button',
		'label' => 'Clear Search',
		'icon' => 'remove',
		'onclick' => 'return diagnostics_reset_cdr_form();',
		'style' => 'margin-left: 8px;',
	]);

	echo "				</td>\n";
	echo "			</tr>\n";
	echo "			</table>\n";
	if (!empty($cdr_match_count_errors)) {
		echo "			<br />\n";
		echo "			<div class='message_text message_mood_alert' style='font-size: 1.05em; font-weight: 700; padding: 10px 12px;'>\n";
		echo "				<ul style='margin: 0 0 0 18px; padding: 0;'>\n";
		foreach ($cdr_match_count_errors as $cdr_error) {
			echo "					<li>".escape((string) $cdr_error)."</li>\n";
		}
		echo "				</ul>\n";
		echo "			</div>\n";
	}
	if (is_array($cdr_match_preview)) {
		$preview_warnings = '';
		if (is_array($cdr_match_preview['warnings'] ?? null)) {
			$warning_items = [];
			foreach ($cdr_match_preview['warnings'] as $cdr_warning) {
				$cdr_warning = trim((string) $cdr_warning);
				if ($cdr_warning !== '') {
					$warning_items[] = $cdr_warning;
				}
			}
			$preview_warnings = implode('; ', $warning_items);
		}
		elseif (is_string($cdr_match_preview['warnings'] ?? null)) {
			$preview_warnings = trim((string) $cdr_match_preview['warnings']);
		}
		$preview_errors = '';
		if (is_array($cdr_match_preview['errors'] ?? null)) {
			$error_items = [];
			foreach ($cdr_match_preview['errors'] as $cdr_error) {
				$cdr_error = trim((string) $cdr_error);
				if ($cdr_error !== '') {
					$error_items[] = $cdr_error;
				}
			}
			$preview_errors = implode('; ', $error_items);
		}
		elseif (is_string($cdr_match_preview['errors'] ?? null)) {
			$preview_errors = trim((string) $cdr_match_preview['errors']);
		}
		$matched_count = (int) ($cdr_match_preview['matched_count'] ?? 0);
		$preview_limit = (int) ($cdr_match_preview['max_records'] ?? 25);
		if ($preview_limit < 1) {
			$preview_limit = 25;
		}
		if ($preview_limit > 100) {
			$preview_limit = 100;
		}
		$match_message = $matched_count === 0 ? 'No matching calls found.' : ($matched_count === 1 ? '1 matching call found.' : $matched_count.' matching calls found.');
		if ($matched_count > $preview_limit) {
			$match_message = 'Showing first '.$preview_limit.' of '.$matched_count.' matching calls. Narrow the search or increase Max Records.';
		}
		$banner_style = $matched_count > 0
			? 'border: 1px solid #b7d7be; background: #eef7ef; color: #2f4f2f;'
			: 'border: 1px solid #d7c8b7; background: #f9f4ef; color: #5a4130;';
		// TODO: If collector-specific colors are ever added, map them to theme/default settings.
		echo "			<br />\n";
		echo "			<div style='".$banner_style." padding: 12px; border-radius: 4px; font-size: 1.15em; font-weight: 700; line-height: 1.4;'>".escape($match_message)."</div>\n";
		echo "			<table class='list diagnostics-detail-table'>\n";
		echo "			<tr class='list-header'><th>CDR Match Count Preview</th><th>Value</th></tr>\n";
		echo "			<tr class='list-row'><td>Matched Count</td><td>".escape((string) ($cdr_match_preview['matched_count'] ?? 0))."</td></tr>\n";
		echo "			<tr class='list-row'><td>Max Records</td><td>".escape((string) ($cdr_match_preview['max_records'] ?? 25))."</td></tr>\n";
		if ($preview_warnings !== '') {
			echo "			<tr class='list-row'><td>Warnings</td><td>".escape($preview_warnings)."</td></tr>\n";
		}
		if ($preview_errors !== '') {
			echo "			<tr class='list-row'><td>Errors</td><td>".escape($preview_errors)."</td></tr>\n";
		}
		if (!empty($cdr_match_preview['effective_filters']) && is_array($cdr_match_preview['effective_filters'])) {
			foreach ($cdr_match_preview['effective_filters'] as $filter_name => $filter_value) {
				if (is_bool($filter_value)) {
					$filter_value = $filter_value ? 'true' : 'false';
				}
				if ($filter_value === null || $filter_value === '') {
					$filter_value = '-';
				}
				echo "			<tr class='list-row'><td>Filter: ".escape((string) $filter_name)."</td><td>".escape((string) $filter_value)."</td></tr>\n";
			}
		}
		echo "			</table>\n";
		echo "			<input type='hidden' name='cdr_preview_matched_count' value=\"".escape((string) $matched_count)."\">\n";
		echo "			<input type='hidden' name='cdr_preview_selected_count' value=\"".escape((string) count($cdr_preview_records))."\">\n";

		if (permission_exists('diagnostics_download') && $preview_errors === '') {
			echo "			<div style='margin: 10px 0 12px 0;'>\n";
			echo button::create([
				'type' => 'submit',
				'label' => 'Download CDR Evidence Bundle',
				'icon' => $settings->get('theme', 'button_icon_download'),
				'onclick' => "var actionField = document.getElementById('cdr_form_action'); if (actionField) { actionField.value='download_cdr_evidence_bundle'; }",
			]);
			echo "			</div>\n";
		}

		if (!empty($cdr_preview_records) && is_array($cdr_preview_records)) {
			$can_view_record = permission_exists('xml_cdr_details');
			$all_domains_scope = (($cdr_filters['scope'] ?? 'current_domain') === 'all_domains');
			echo "			<table class='list'>\n";
			echo "			<tr class='list-header'>\n";
			echo "				<th>Start Time</th>\n";
			echo "				<th>Direction</th>\n";
			echo "				<th>Caller ID Name</th>\n";
			echo "				<th>Caller ID Number</th>\n";
			echo "				<th>Destination</th>\n";
			echo "				<th>Duration</th>\n";
			echo "				<th>Status</th>\n";
			echo "				<th>Hangup Cause</th>\n";
			echo "				<th>Call UUID</th>\n";
			echo "				<th>View Record</th>\n";
			echo "				<th>Recording Present</th>\n";
			echo "			</tr>\n";
			foreach ($cdr_preview_records as $cdr_row) {
				$call_uuid = trim((string) ($cdr_row['call_uuid'] ?? ''));
				$valid_call_uuid = false;
				if ($call_uuid !== '') {
					if (function_exists('is_uuid')) {
						$valid_call_uuid = is_uuid($call_uuid);
					}
					else {
						$valid_call_uuid = (bool) preg_match('/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i', $call_uuid);
					}
				}
				$view_record_link = '';
				if ($can_view_record && $valid_call_uuid) {
					$view_record_link = PROJECT_PATH.'/app/xml_cdr/xml_cdr_details.php?id='.urlencode($call_uuid);
					if ($all_domains_scope) {
						$view_record_link .= '&show=all';
						$row_domain_uuid = trim((string) ($cdr_row['domain_uuid'] ?? ''));
						$session_domain_uuid = trim((string) ($_SESSION['domain_uuid'] ?? ''));
						if (permission_exists('domain_select') && $row_domain_uuid !== '' && $row_domain_uuid !== $session_domain_uuid) {
							$view_record_link .= '&domain_uuid='.urlencode($row_domain_uuid).'&domain_change=true';
						}
					}
				}
				echo "			<tr class='list-row'>\n";
				echo "				<td>".escape((string) ($cdr_row['start_time'] ?? ''))."</td>\n";
				echo "				<td>".escape((string) ($cdr_row['direction'] ?? ''))."</td>\n";
				echo "				<td>".escape((string) ($cdr_row['caller_id_name'] ?? ''))."</td>\n";
				echo "				<td>".escape((string) ($cdr_row['caller_id_number'] ?? ''))."</td>\n";
				echo "				<td>".escape((string) ($cdr_row['destination'] ?? ''))."</td>\n";
				echo "				<td>".escape((string) ($cdr_row['duration'] ?? ''))."</td>\n";
				echo "				<td>".escape((string) ($cdr_row['status'] ?? ''))."</td>\n";
				echo "				<td>".escape((string) ($cdr_row['hangup_cause'] ?? ''))."</td>\n";
				echo "				<td class='diagnostics-hash'>".escape($call_uuid)."</td>\n";
				if ($view_record_link !== '') {
					echo "				<td><a href='".escape($view_record_link)."'>View Record</a></td>\n";
				}
				else {
					echo "				<td>-</td>\n";
				}
				echo "				<td>".(!empty($cdr_row['recording_present']) ? 'Yes' : 'No')."</td>\n";
				echo "			</tr>\n";
			}
			echo "			</table>\n";
		}
	}
	echo "			</form>\n";
	echo "		</div>\n";
	echo "	</td>\n";
	echo "</tr>\n";
	echo "</table>\n";
	echo "</div>\n";
	echo "<br />\n";

	echo "<div class='card'>\n";
	echo "<table class='list'>\n";
	echo "<tr class='list-header'>\n";
	echo "	<th>".$text['label-current_and_planned_sections']."</th>\n";
	echo "	<th>Status</th>\n";
	echo "	<th>Scope</th>\n";
	echo "	<th>Record Count</th>\n";
	echo "</tr>\n";
	$row_id = 0;
	foreach ($section_groups as $group) {
		$row_id++;
		$group_id = 'diagnostics_group_'.$row_id;
		$group_count = count($group['sections']);
		$group_statuses = array_unique(array_column($group['sections'], 'status'));
		$group_status = count($group_statuses) === 1 ? reset($group_statuses) : 'mixed';
		echo "<tr class='list-row diagnostics-toggle' onclick=\"diagnostics_toggle('".$group_id."')\">\n";
		echo "	<td><span class='diagnostics-caret' id='".$group_id."_caret'>&#9656;</span><b>".escape($group['name'])."</b></td>\n";
		echo "	<td>".escape($group_status)."</td>\n";
		echo "	<td>mixed</td>\n";
		echo "	<td>".escape($group_count)." sections</td>\n";
		echo "</tr>\n";
		echo "<tr class='list-row diagnostics-details' id='".$group_id."'>\n";
		echo "	<td colspan='4'>\n";
		echo "		<table class='list'>\n";
		foreach ($group['sections'] as $section) {
			$row_id++;
			$detail_id = 'diagnostics_section_'.$row_id;
			$has_details = !empty($section['details_type']) && !empty($section['details']);
			echo "		<tr class='list-row".($has_details ? " diagnostics-toggle" : "")."'".($has_details ? " onclick=\"diagnostics_toggle('".$detail_id."'); event.stopPropagation();\"" : "").">\n";
			echo "			<td class='diagnostics-child'>";
			if ($has_details) {
				echo "<span class='diagnostics-caret' id='".$detail_id."_caret'>&#9656;</span>";
			}
			else {
				echo "<span class='diagnostics-caret'>&nbsp;</span>";
			}
			echo escape($section['name'])."</td>\n";
			echo "			<td>".escape($section['status'])."</td>\n";
			echo "			<td>".escape($section['scope'])."</td>\n";
			echo "			<td>".escape($section['record_count'])."</td>\n";
			echo "		</tr>\n";
			if ($has_details) {
				echo "		<tr class='list-row diagnostics-details' id='".$detail_id."'>\n";
				echo "			<td colspan='4'>\n";
				echo "				<div class='diagnostics-child'>\n";
				if ($section['details_type'] === 'system') {
					$details = $section['details'];
					$system_rows = [
						'Collector Version' => $details['collector_version'] ?? '',
						'Schema Version' => $details['schema_version'] ?? '',
						'Generated At' => $details['generated_at'] ?? '',
						'FusionPBX Version' => $details['fusionpbx']['version'] ?? '',
						'PHP Version' => $details['fusionpbx']['php_version'] ?? '',
						'Database Type' => $details['fusionpbx']['database_type'] ?? '',
						'Database Driver' => $details['fusionpbx']['database_driver'] ?? '',
						'Current Domain UUID' => $details['current_domain']['domain_uuid'] ?? '',
						'Current Domain Name' => $details['current_domain']['domain_name'] ?? '',
						'Current User UUID' => $details['current_user']['user_uuid'] ?? '',
						'Warnings' => !empty($details['warnings']) ? implode(', ', $details['warnings']) : '-',
					];
					echo "					<table class='list diagnostics-detail-table'>\n";
					foreach ($system_rows as $label => $value) {
						echo "					<tr class='list-row'>\n";
						echo "						<td>".escape($label)."</td>\n";
						echo "						<td>".escape($value)."</td>\n";
						echo "					</tr>\n";
					}
					echo "					</table>\n";
				}
				if ($section['details_type'] === 'domains') {
					$details = $section['details'];
					$warnings = !empty($details['warnings']) ? implode(', ', $details['warnings']) : '-';
					echo "					<table class='list'>\n";
					echo "					<tr class='list-header'>\n";
					echo "						<th>Domain</th>\n";
					echo "						<th>Enabled</th>\n";
					echo "						<th>UUID</th>\n";
					echo "						<th>Warnings</th>\n";
					echo "					</tr>\n";
					if (!empty($details['data'])) {
						foreach ($details['data'] as $index => $domain) {
							echo "					<tr class='list-row'>\n";
							echo "						<td>".escape($domain['domain_name'] ?? '')."</td>\n";
							echo "						<td>".escape($domain['domain_enabled'] ?? '')."</td>\n";
							echo "						<td class='diagnostics-hash'>".escape($domain['domain_uuid'] ?? '')."</td>\n";
							echo "						<td>".escape($index === 0 ? $warnings : '-')."</td>\n";
							echo "					</tr>\n";
						}
					}
					else {
						echo "					<tr class='list-row'>\n";
						echo "						<td colspan='4'>".escape($warnings)."</td>\n";
						echo "					</tr>\n";
					}
					echo "					</table>\n";
				}
				if ($section['details_type'] === 'extensions') {
					$details = $section['details'];
					$warnings = !empty($details['warnings']) ? implode(', ', $details['warnings']) : '-';
					echo "					<table class='list'>\n";
					echo "					<tr class='list-header'>\n";
					echo "						<th>Extension</th>\n";
					echo "						<th>Number Alias</th>\n";
					echo "						<th>Enabled</th>\n";
					echo "						<th>Voicemail</th>\n";
					echo "						<th>Directory</th>\n";
					echo "						<th>DND</th>\n";
					echo "						<th>User Context</th>\n";
					echo "						<th>UUID</th>\n";
					echo "					</tr>\n";
					if (!empty($details['data'])) {
						foreach ($details['data'] as $extension) {
							echo "					<tr class='list-row'>\n";
							echo "						<td>".escape($extension['extension'] ?? '')."</td>\n";
							echo "						<td>".escape($extension['number_alias'] ?? '')."</td>\n";
							echo "						<td>".escape($extension['enabled'] ?? '')."</td>\n";
							echo "						<td>".escape($extension['voicemail_enabled'] ?? '-')."</td>\n";
							echo "						<td>".escape($extension['directory_visible'] ?? '')."</td>\n";
							echo "						<td>".escape($extension['do_not_disturb'] ?? '')."</td>\n";
							echo "						<td>".escape($extension['user_context'] ?? '')."</td>\n";
							echo "						<td class='diagnostics-hash'>".escape($extension['extension_uuid'] ?? '')."</td>\n";
							echo "					</tr>\n";
						}
					}
					else {
						echo "					<tr class='list-row'>\n";
						echo "						<td colspan='8'>".escape($warnings)."</td>\n";
						echo "					</tr>\n";
					}
					if ($warnings !== '-') {
					echo "					<tr class='list-row'>\n";
					echo "						<td colspan='8'>Warnings: ".escape($warnings)."</td>\n";
					echo "					</tr>\n";
					}
					echo "					</table>\n";
				}
				if ($section['details_type'] === 'gateways') {
					$details = $section['details'];
					$warnings = !empty($details['warnings']) ? implode(', ', $details['warnings']) : '-';
					echo "					<table class='list'>\n";
					echo "					<tr class='list-header'>\n";
					echo "						<th>Gateway</th>\n";
					echo "						<th>Enabled</th>\n";
					echo "						<th>Register</th>\n";
					echo "						<th>Profile</th>\n";
					echo "						<th>Transport</th>\n";
					echo "						<th>Proxy</th>\n";
					echo "						<th>Realm</th>\n";
					echo "						<th>From Domain</th>\n";
					echo "						<th>UUID</th>\n";
					echo "					</tr>\n";
					if (!empty($details['data'])) {
						foreach ($details['data'] as $gateway) {
							echo "					<tr class='list-row'>\n";
							echo "						<td>".escape($gateway['gateway'] ?? '')."</td>\n";
							echo "						<td>".escape($gateway['enabled'] ?? '')."</td>\n";
							echo "						<td>".escape($gateway['register'] ?? '')."</td>\n";
							echo "						<td>".escape($gateway['profile'] ?? '')."</td>\n";
							echo "						<td>".escape($gateway['transport'] ?? '')."</td>\n";
							echo "						<td>".escape($gateway['proxy'] ?? '')."</td>\n";
							echo "						<td>".escape($gateway['realm'] ?? '')."</td>\n";
							echo "						<td>".escape($gateway['from_domain'] ?? '')."</td>\n";
							echo "						<td class='diagnostics-hash'>".escape($gateway['gateway_uuid'] ?? '')."</td>\n";
							echo "					</tr>\n";
						}
					}
					else {
						echo "					<tr class='list-row'>\n";
						echo "						<td colspan='9'>".escape($warnings)."</td>\n";
						echo "					</tr>\n";
					}
					echo "					</table>\n";
				}
				if ($section['details_type'] === 'access_controls') {
					$details = $section['details'];
					$warnings = !empty($details['warnings']) ? implode(', ', $details['warnings']) : '-';
					echo "					<table class='list'>\n";
					echo "					<tr class='list-header'>\n";
					echo "						<th>ACL</th>\n";
					echo "						<th>Enabled</th>\n";
					echo "						<th>Default Action</th>\n";
					echo "						<th>Node Count</th>\n";
					echo "						<th>IPv4 Nodes</th>\n";
					echo "						<th>IPv6 Nodes</th>\n";
					echo "						<th>Nodes</th>\n";
					echo "						<th>UUID</th>\n";
					echo "					</tr>\n";
					if (!empty($details['data'])) {
						foreach ($details['data'] as $acl) {
							$node_values = [];
							if (!empty($acl['nodes'])) {
								foreach (array_slice($acl['nodes'], 0, 3) as $node) {
									$node_values[] = trim(($node['node_type'] ?? '').' '.($node['node_cidr'] ?? ''));
								}
							}
							$nodes_summary = !empty($node_values) ? implode(', ', $node_values) : '-';
							if (($acl['node_count'] ?? 0) > 3) {
								$nodes_summary .= ' ...';
							}
							echo "					<tr class='list-row'>\n";
							echo "						<td>".escape($acl['access_control_name'] ?? '')."</td>\n";
							echo "						<td>".escape($acl['enabled'] ?? '-')."</td>\n";
							echo "						<td>".escape($acl['default_action'] ?? '')."</td>\n";
							echo "						<td>".escape($acl['node_count'] ?? 0)."</td>\n";
							echo "						<td>".escape($acl['ipv4_node_count'] ?? 0)."</td>\n";
							echo "						<td>".escape($acl['ipv6_node_count'] ?? 0)."</td>\n";
							echo "						<td>".escape($nodes_summary)."</td>\n";
							echo "						<td class='diagnostics-hash'>".escape($acl['access_control_uuid'] ?? '')."</td>\n";
							echo "					</tr>\n";
						}
					}
					else {
						echo "					<tr class='list-row'>\n";
						echo "						<td colspan='8'>".escape($warnings)."</td>\n";
						echo "					</tr>\n";
					}
					if ($warnings !== '-') {
						echo "					<tr class='list-row'>\n";
						echo "						<td colspan='8'>Warnings: ".escape($warnings)."</td>\n";
						echo "					</tr>\n";
					}
					echo "					</table>\n";
				}

				
				if ($section['details_type'] === 'dialplans') {
					$details = $section['details'];
					$warnings = !empty($details['warnings']) ? implode(', ', $details['warnings']) : '-';
					echo "\t\t\t\t\t<table class='list'>\n";
					echo "\t\t\t\t\t<tr class='list-header'>\n";
					echo "\t\t\t\t\t\t<th>Dialplan</th>\n";
					echo "\t\t\t\t\t\t<th>Enabled</th>\n";
					echo "\t\t\t\t\t\t<th>Category</th>\n";
					echo "\t\t\t\t\t\t<th>Context</th>\n";
					echo "\t\t\t\t\t\t<th>Details</th>\n";
					echo "\t\t\t\t\t\t<th>Conditions</th>\n";
					echo "\t\t\t\t\t\t<th>Actions</th>\n";
					echo "\t\t\t\t\t\t<th>Order</th>\n";
					echo "\t\t\t\t\t\t<th>UUID</th>\n";
					echo "\t\t\t\t\t</tr>\n";
					if (!empty($details['data'])) {
						foreach ($details['data'] as $dialplan) {
							echo "\t\t\t\t\t<tr class='list-row'>\n";
							echo "\t\t\t\t\t\t<td>".escape($dialplan['dialplan_name'] ?? '')."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($dialplan['enabled'] ?? '')."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($dialplan['category'] ?? '-')."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($dialplan['context'] ?? '')."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($dialplan['detail_count'] ?? 0)."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($dialplan['condition_count'] ?? 0)."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($dialplan['action_count'] ?? 0)."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($dialplan['order'] ?? '')."</td>\n";
							echo "\t\t\t\t\t\t<td class='diagnostics-hash'>".escape($dialplan['dialplan_uuid'] ?? '')."</td>\n";
							echo "\t\t\t\t\t</tr>\n";
						}
					}
					else {
						echo "\t\t\t\t\t<tr class='list-row'>\n";
						echo "\t\t\t\t\t\t<td colspan='9'>".escape($warnings)."</td>\n";
						echo "\t\t\t\t\t</tr>\n";
					}
					if ($warnings !== '-') {
						echo "\t\t\t\t\t<tr class='list-row'>\n";
						echo "\t\t\t\t\t\t<td colspan='9'>Warnings: ".escape($warnings)."</td>\n";
						echo "\t\t\t\t\t</tr>\n";
					}
					echo "\t\t\t\t\t</table>\n";
				}

				
				if ($section['details_type'] === 'destinations') {
					$details = $section['details'];
					$warnings = !empty($details['warnings']) ? implode(', ', $details['warnings']) : '-';
					echo "\t\t\t\t\t<table class='list'>\n";
					echo "\t\t\t\t\t<tr class='list-header'>\n";
					echo "\t\t\t\t\t\t<th>Destination</th>\n";
					echo "\t\t\t\t\t\t<th>Enabled</th>\n";
					echo "\t\t\t\t\t\t<th>Type</th>\n";
					echo "\t\t\t\t\t\t<th>Context</th>\n";
					echo "\t\t\t\t\t\t<th>Action</th>\n";
					echo "\t\t\t\t\t\t<th>UUID</th>\n";
					echo "\t\t\t\t\t</tr>\n";
					if (!empty($details['data'])) {
						foreach ($details['data'] as $destination) {
							echo "\t\t\t\t\t<tr class='list-row'>\n";
							echo "\t\t\t\t\t\t<td>".escape($destination['destination'] ?? '')."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($destination['enabled'] ?? '')."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($destination['type'] ?? '')."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($destination['context'] ?? '')."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($destination['action'] ?? '')."</td>\n";
							echo "\t\t\t\t\t\t<td class='diagnostics-hash'>".escape($destination['destination_uuid'] ?? '')."</td>\n";
							echo "\t\t\t\t\t</tr>\n";
						}
					}
					else {
						echo "\t\t\t\t\t<tr class='list-row'>\n";
						echo "\t\t\t\t\t\t<td colspan='6'>".escape($warnings)."</td>\n";
						echo "\t\t\t\t\t</tr>\n";
					}
					if ($warnings !== '-') {
						echo "\t\t\t\t\t<tr class='list-row'>\n";
						echo "\t\t\t\t\t\t<td colspan='6'>Warnings: ".escape($warnings)."</td>\n";
						echo "\t\t\t\t\t</tr>\n";
					}
					echo "\t\t\t\t\t</table>\n";
				}

				if ($section['details_type'] === 'sip_profiles') {
					$details = $section['details'];
					$warnings = !empty($details['warnings']) ? implode(', ', $details['warnings']) : '-';
					echo "\t\t\t\t\t<table class='list'>\n";
					echo "\t\t\t\t\t<tr class='list-header'>\n";
					echo "\t\t\t\t\t\t<th>Profile</th>\n";
					echo "\t\t\t\t\t\t<th>Enabled</th>\n";
					echo "\t\t\t\t\t\t<th>Domains</th>\n";
					echo "\t\t\t\t\t\t<th>Settings</th>\n";
					echo "\t\t\t\t\t\t<th>UUID</th>\n";
					echo "\t\t\t\t\t</tr>\n";
					if (!empty($details['data'])) {
						foreach ($details['data'] as $profile) {
							$domain_names = [];
							if (!empty($profile['domains'])) {
								foreach ($profile['domains'] as $domain) {
									if (!empty($domain['name'])) {
										$domain_names[] = $domain['name'];
									}
								}
							}
							$domains = !empty($domain_names) ? implode(', ', $domain_names) : escape($profile['domain_count'] ?? 0);
							echo "\t\t\t\t\t<tr class='list-row'>\n";
							echo "\t\t\t\t\t\t<td>".escape($profile['profile'] ?? '')."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($profile['enabled'] ?? '')."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($domains)."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($profile['setting_count'] ?? 0)."</td>\n";
							echo "\t\t\t\t\t\t<td class='diagnostics-hash'>".escape($profile['sip_profile_uuid'] ?? '')."</td>\n";
							echo "\t\t\t\t\t</tr>\n";
						}
					}
					else {
						echo "\t\t\t\t\t<tr class='list-row'>\n";
						echo "\t\t\t\t\t\t<td colspan='5'>".escape($warnings)."</td>\n";
						echo "\t\t\t\t\t</tr>\n";
					}
					if ($warnings !== '-') {
						echo "\t\t\t\t\t<tr class='list-row'>\n";
						echo "\t\t\t\t\t\t<td colspan='5'>Warnings: ".escape($warnings)."</td>\n";
						echo "\t\t\t\t\t</tr>\n";
					}
					echo "\t\t\t\t\t</table>\n";
				}

				if ($section['details_type'] === 'variables') {
					$details = $section['details'];
					$warnings = !empty($details['warnings']) ? implode(', ', $details['warnings']) : '-';
					echo "\t\t\t\t\t<table class='list'>\n";
					echo "\t\t\t\t\t<tr class='list-header'>\n";
					echo "\t\t\t\t\t\t<th>Category</th>\n";
					echo "\t\t\t\t\t\t<th>Name</th>\n";
					echo "\t\t\t\t\t\t<th>Value</th>\n";
					echo "\t\t\t\t\t\t<th>Enabled</th>\n";
					echo "\t\t\t\t\t\t<th>UUID</th>\n";
					echo "\t\t\t\t\t</tr>\n";
					if (!empty($details['data'])) {
						foreach ($details['data'] as $variable) {
							echo "\t\t\t\t\t<tr class='list-row'>\n";
							echo "\t\t\t\t\t\t<td>".escape($variable['category'] ?? '')."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($variable['name'] ?? '')."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($variable['value'] ?? '')."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($variable['enabled'] ?? '')."</td>\n";
							echo "\t\t\t\t\t\t<td class='diagnostics-hash'>".escape($variable['var_uuid'] ?? '')."</td>\n";
							echo "\t\t\t\t\t</tr>\n";
						}
					}
					else {
						echo "\t\t\t\t\t<tr class='list-row'>\n";
						echo "\t\t\t\t\t\t<td colspan='5'>".escape($warnings)."</td>\n";
						echo "\t\t\t\t\t</tr>\n";
					}
					if ($warnings !== '-') {
						echo "\t\t\t\t\t<tr class='list-row'>\n";
						echo "\t\t\t\t\t\t<td colspan='5'>Warnings: ".escape($warnings)."</td>\n";
						echo "\t\t\t\t\t</tr>\n";
					}
					echo "\t\t\t\t\t</table>\n";
				}
				if ($section['details_type'] === 'sip_status') {
					$details = $section['details'];
					$warnings = !empty($details['warnings']) ? implode(', ', $details['warnings']) : '-';
					echo "\t\t\t\t\t<table class='list'>\n";
					echo "\t\t\t\t\t<tr class='list-header'>\n";
					echo "\t\t\t\t\t\t<th>Type</th>\n";
					echo "\t\t\t\t\t\t<th>Name</th>\n";
					echo "\t\t\t\t\t\t<th>Profile</th>\n";
					echo "\t\t\t\t\t\t<th>Status</th>\n";
					echo "\t\t\t\t\t\t<th>State</th>\n";
					echo "\t\t\t\t\t\t<th>Host/IP</th>\n";
					echo "\t\t\t\t\t\t<th>Details</th>\n";
					echo "\t\t\t\t\t</tr>\n";
					if (!empty($details['data'])) {
						foreach ($details['data'] as $status) {
							$details_summary = [];
							if (!empty($status['domain'])) {
								$details_summary[] = 'domain '.$status['domain'];
							}
							if (!empty($status['details']) && is_array($status['details'])) {
								$details_summary[] = count($status['details']).' fields';
							}
							echo "\t\t\t\t\t<tr class='list-row'>\n";
							echo "\t\t\t\t\t\t<td>".escape($status['type'] ?? '')."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($status['name'] ?? '')."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($status['profile'] ?? '')."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($status['status'] ?? '')."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($status['state'] ?? '')."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($status['host_ip'] ?? '')."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape(!empty($details_summary) ? implode(', ', $details_summary) : '-')."</td>\n";
							echo "\t\t\t\t\t</tr>\n";
						}
					}
					else {
						echo "\t\t\t\t\t<tr class='list-row'>\n";
						echo "\t\t\t\t\t\t<td colspan='7'>".escape($warnings)."</td>\n";
						echo "\t\t\t\t\t</tr>\n";
					}
					if ($warnings !== '-') {
						echo "\t\t\t\t\t<tr class='list-row'>\n";
						echo "\t\t\t\t\t\t<td colspan='7'>Warnings: ".escape($warnings)."</td>\n";
						echo "\t\t\t\t\t</tr>\n";
					}
					echo "\t\t\t\t\t</table>\n";
				}

				if ($section['details_type'] === 'registrations') {
					$details = $section['details'];
					$warnings = !empty($details['warnings']) ? implode(', ', $details['warnings']) : '-';
					echo "\t\t\t\t\t<table class='list'>\n";
					echo "\t\t\t\t\t<tr class='list-header'>\n";
					echo "\t\t\t\t\t\t<th>User/Extension</th>\n";
					echo "\t\t\t\t\t\t<th>Domain</th>\n";
					echo "\t\t\t\t\t\t<th>Profile</th>\n";
					echo "\t\t\t\t\t\t<th>User Agent</th>\n";
					echo "\t\t\t\t\t\t<th>Contact</th>\n";
					echo "\t\t\t\t\t\t<th>Network</th>\n";
					echo "\t\t\t\t\t\t<th>Status</th>\n";
					echo "\t\t\t\t\t</tr>\n";
					if (!empty($details['data'])) {
						foreach ($details['data'] as $registration) {
							$status = $registration['status'] ?? '';
							if (!empty($registration['ping_status'])) {
								$status = trim($status.' / '.$registration['ping_status']);
							}
							echo "\t\t\t\t\t<tr class='list-row'>\n";
							echo "\t\t\t\t\t\t<td>".escape($registration['user'] ?? ($registration['extension'] ?? ''))."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($registration['domain'] ?? '')."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($registration['profile'] ?? '')."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($registration['user_agent'] ?? '')."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($registration['contact'] ?? '')."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($registration['network'] ?? '')."</td>\n";
							echo "\t\t\t\t\t\t<td>".escape($status)."</td>\n";
							echo "\t\t\t\t\t</tr>\n";
						}
					}
					else {
						echo "\t\t\t\t\t<tr class='list-row'>\n";
						echo "\t\t\t\t\t\t<td colspan='7'>".escape($warnings)."</td>\n";
						echo "\t\t\t\t\t</tr>\n";
					}
					if ($warnings !== '-') {
						echo "\t\t\t\t\t<tr class='list-row'>\n";
						echo "\t\t\t\t\t\t<td colspan='7'>Warnings: ".escape($warnings)."</td>\n";
						echo "\t\t\t\t\t</tr>\n";
					}
					echo "\t\t\t\t\t</table>\n";
				}

				$raw_id = $detail_id.'_raw';
				$raw_json = json_encode($section['details'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
				echo "				<br />\n";
				echo "				<table class='list'>\n";
				echo "				<tr class='list-row diagnostics-toggle' onclick=\"diagnostics_toggle('".$raw_id."'); event.stopPropagation();\">\n";
				echo "					<td><span class='diagnostics-caret' id='".$raw_id."_caret'>&#9656;</span>Raw JSON</td>\n";
				echo "				</tr>\n";
				echo "				<tr class='list-row diagnostics-details' id='".$raw_id."'>\n";
				echo "					<td><pre class='diagnostics-raw-json'>".escape($raw_json)."</pre></td>\n";
				echo "				</tr>\n";
				echo "				</table>\n";
				echo "				</div>\n";
				echo "			</td>\n";
				echo "		</tr>\n";
			}
		}
		echo "		</table>\n";
		echo "	</td>\n";
		echo "</tr>\n";
	}
	echo "</table>\n";
	echo "</div>\n";

//include the footer
	require_once "resources/footer.php";

?>
