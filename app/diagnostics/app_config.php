<?php

	//application details
		$apps[$x]['name'] = "Diagnostics";
		$apps[$x]['uuid'] = "59a2e9c2-438e-4e9f-b8d0-5df7d3dd7e20";
		$apps[$x]['category'] = "Applications";
		$apps[$x]['subcategory'] = "";
		$apps[$x]['version'] = "1.0";
		$apps[$x]['license'] = "Mozilla Public License 1.1";
		$apps[$x]['url'] = "http://www.fusionpbx.com";
		$apps[$x]['description']['en-us'] = "Read-only diagnostics framework for support bundle collection and reporting.";
		$apps[$x]['description']['en-gb'] = "Read-only diagnostics framework for support bundle collection and reporting.";

	//permission details
		$y=0;
		$apps[$x]['permissions'][$y]['name'] = "diagnostics_view";
		$apps[$x]['permissions'][$y]['menu']['uuid'] = "f3eb72dd-9ef7-4b3d-bef7-53dd6f05fa10";
		$apps[$x]['permissions'][$y]['groups'][] = "superadmin";
		$y++;
		$apps[$x]['permissions'][$y]['name'] = "diagnostics_collect";
		$apps[$x]['permissions'][$y]['groups'][] = "superadmin";
		$y++;
		$apps[$x]['permissions'][$y]['name'] = "diagnostics_download";
		$apps[$x]['permissions'][$y]['groups'][] = "superadmin";
		$y++;
		$apps[$x]['permissions'][$y]['name'] = "diagnostics_reports";
		$apps[$x]['permissions'][$y]['groups'][] = "superadmin";
		$y++;
		$apps[$x]['permissions'][$y]['name'] = "diagnostics_audit";
		$apps[$x]['permissions'][$y]['groups'][] = "superadmin";
		$y++;
		$apps[$x]['permissions'][$y]['name'] = "diagnostics_admin";
		$apps[$x]['permissions'][$y]['groups'][] = "superadmin";

?>
