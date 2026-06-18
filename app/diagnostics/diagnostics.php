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

//check permissions
	if (!permission_exists('diagnostics_view')) {
		echo "access denied";
		exit;
	}

//add multi-lingual support
	$language = new text;
	$text = $language->get();

//include the header
	$document['title'] = $text['title-diagnostics'];
	require_once "resources/header.php";

//show the content
	echo "<div class='action_bar' id='action_bar'>\n";
	echo "	<div class='heading'><b>".$text['header-diagnostics']."</b></div>\n";
	echo "	<div class='actions'>\n";
	if (permission_exists('diagnostics_collect')) {
		echo button::create(['type'=>'button','label'=>$text['button-collect_diagnostics'],'icon'=>$settings->get('theme', 'button_icon_download'),'link'=>'diagnostic_collect.php']);
	}
	if (permission_exists('diagnostics_reports')) {
		echo button::create(['type'=>'button','label'=>$text['button-reports'],'icon'=>'chart-simple','link'=>'reports.php']);
	}
	if (permission_exists('diagnostics_audit')) {
		echo button::create(['type'=>'button','label'=>$text['button-audits'],'icon'=>'list-check','link'=>'audits.php']);
	}
	echo "	</div>\n";
	echo "	<div style='clear: both;'></div>\n";
	echo "</div>\n";

	echo $text['description-diagnostics']."\n";
	echo "<br /><br />\n";

	echo "<div class='card'>\n";
	echo "<table class='list'>\n";
	echo "<tr class='list-header'>\n";
	echo "	<th>".$text['label-phase_1_framework']."</th>\n";
	echo "</tr>\n";
	echo "<tr class='list-row'>\n";
	echo "	<td>".$text['label-read_only_collector_planned']."</td>\n";
	echo "</tr>\n";
	echo "</table>\n";
	echo "</div>\n";

//include the footer
	require_once "resources/footer.php";

?>
