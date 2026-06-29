<?php

/**
 * diagnostic collector
 */
	class diagnostic_collector {

		/**
		 * Collector version.
		 *
		 * @var string
		 */
		const COLLECTOR_VERSION = '0.1';

		/**
		 * Schema version.
		 *
		 * @var string
		 */
		const SCHEMA_VERSION = '1.0.0';

		/**
		 * Collect all currently available diagnostic section objects.
		 *
		 * @param array $options
		 * @return array
		 */
		public function collect_sections($options = []) {
			return [
				'system' => $this->collect_system_preview(),
				'domains' => $this->collect_domains_preview(),
				'extensions' => $this->collect_extensions_preview(),
				'gateways' => $this->collect_gateways_preview(),
				'access_controls' => $this->collect_access_controls_preview(),
				'dialplans' => $this->collect_dialplans_preview(),
				'destinations' => $this->collect_destinations_preview(),
				'sip_profiles' => $this->collect_sip_profiles_preview(),
				'variables' => $this->collect_variables_preview(),
				'registrations' => $this->collect_registrations_preview(),
				'sip_status' => $this->collect_sip_status_preview(),
			];
		}


		/**
		 * Count matching detailed CDR records for the optional CDR preview.
		 *
		 * @param array $filters
		 * @return array
		 */
		public function collect_cdr_detailed_match_count($filters = []) {
			global $database;

			$warnings = [];
			$errors = [];
			$max_records = isset($filters['max_records']) ? (int) $filters['max_records'] : 25;
			if ($max_records < 1) {
				$max_records = 25;
				$warnings[] = 'Max records was below 1 and was reset to 25.';
			}
			if ($max_records > 100) {
				$max_records = 100;
				$warnings[] = 'Max records is limited to 100.';
			}

			$scope_input = trim((string) ($filters['scope'] ?? 'current_domain'));
			$effective_filters = [
				'scope' => 'current domain',
				'domain_uuid' => $_SESSION['domain_uuid'] ?? null,
				'start_datetime' => trim((string) ($filters['start_datetime'] ?? '')),
				'end_datetime' => trim((string) ($filters['end_datetime'] ?? '')),
				'destination_number' => trim((string) ($filters['destination_number'] ?? '')),
				'caller_id' => trim((string) ($filters['caller_id'] ?? '')),
				'extension' => trim((string) ($filters['extension'] ?? '')),
				'call_uuid' => trim((string) ($filters['call_uuid'] ?? '')),
				'include_logs' => !empty($filters['include_logs']),
			];

			if (!permission_exists('diagnostics_collect')) {
				return [
					'matched_count' => 0,
					'effective_filters' => $effective_filters,
					'max_records' => $max_records,
					'warnings' => $warnings,
					'errors' => ['diagnostics_collect permission required.'],
				];
			}

			if (!permission_exists('xml_cdr_view')) {
				return [
					'matched_count' => 0,
					'effective_filters' => $effective_filters,
					'max_records' => $max_records,
					'warnings' => $warnings,
					'errors' => ['xml_cdr_view permission required.'],
				];
			}

			if (!is_object($database)) {
				return [
					'matched_count' => 0,
					'effective_filters' => $effective_filters,
					'max_records' => $max_records,
					'warnings' => $warnings,
					'errors' => ['database connection unavailable.'],
				];
			}

			$all_domains_requested = $scope_input === 'all_domains';
			$all_domains_allowed = $all_domains_requested && permission_exists('xml_cdr_all');
			if ($all_domains_requested && !$all_domains_allowed) {
				$warnings[] = 'All-domain search requested without xml_cdr_all permission. Using current domain only.';
			}
			if ($all_domains_allowed) {
				$effective_filters['scope'] = 'all domains';
				$effective_filters['domain_uuid'] = null;
			}
			else {
				$effective_filters['scope'] = 'current domain';
				if (empty($effective_filters['domain_uuid'])) {
					$errors[] = 'Current domain is missing for scoped CDR search.';
				}
			}

			$time_zone_name = date_default_timezone_get();
			if (class_exists('settings')) {
				try {
					$settings = new settings;
					$domain_time_zone = $settings->get('domain', 'time_zone', $time_zone_name);
					if (!empty($domain_time_zone)) {
						$time_zone_name = $domain_time_zone;
					}
				}
				catch (Throwable $e) {
					$warnings[] = 'Domain timezone unavailable; using server timezone for datetime parsing.';
				}
			}
			$time_zone = new DateTimeZone($time_zone_name);

			$call_uuid = $effective_filters['call_uuid'];
			if ($call_uuid !== '' && function_exists('is_uuid') && !is_uuid($call_uuid)) {
				$errors[] = 'Call UUID must be a valid UUID.';
			}

			$start_datetime_raw = $effective_filters['start_datetime'];
			$end_datetime_raw = $effective_filters['end_datetime'];
			$start_datetime = null;
			$end_datetime = null;
			$has_start = $start_datetime_raw !== '';
			$has_end = $end_datetime_raw !== '';

			$parse_datetime = function($value) use ($time_zone) {
				$formats = ['Y-m-d\TH:i', 'Y-m-d\TH:i:s', 'Y-m-d H:i', 'Y-m-d H:i:s'];
				foreach ($formats as $format) {
					$dt = DateTime::createFromFormat($format, $value, $time_zone);
					if ($dt instanceof DateTime) {
						$errors_local = DateTime::getLastErrors();
						if (($errors_local['warning_count'] ?? 0) === 0 && ($errors_local['error_count'] ?? 0) === 0) {
							return $dt;
						}
					}
				}
				return null;
			};

			$destination_filter = $effective_filters['destination_number'] !== '';
			$caller_filter = $effective_filters['caller_id'] !== '';
			$extension_filter = $effective_filters['extension'] !== '';
			$call_uuid_filter = $call_uuid !== '';
			$datetime_filter = $has_start && $has_end;

			if ($has_start && !$has_end) {
				$errors[] = 'End Datetime is required when Start Datetime is provided.';
			}
			if ($has_end && !$has_start) {
				$errors[] = 'Start Datetime is required when End Datetime is provided.';
			}

			if (!$datetime_filter && !$destination_filter && !$caller_filter && !$extension_filter && !$call_uuid_filter) {
				$errors[] = 'Enter at least one search filter.';
			}

			if ($has_start && $has_end) {
				$start_datetime = $parse_datetime($start_datetime_raw);
				$end_datetime = $parse_datetime($end_datetime_raw);
				if (!$start_datetime) {
					$errors[] = 'Invalid Start Datetime format. Use YYYY-MM-DDTHH:MM.';
				}
				if (!$end_datetime) {
					$errors[] = 'Invalid End Datetime format. Use YYYY-MM-DDTHH:MM.';
				}
				if ($start_datetime && $end_datetime) {
					if ($end_datetime <= $start_datetime) {
						$errors[] = 'End Datetime must be after Start Datetime.';
					}
					else {
						$max_end_datetime = clone $start_datetime;
						$max_end_datetime->modify('+6 months');
						if ($end_datetime > $max_end_datetime) {
							$errors[] = 'Datetime range cannot exceed 6 months.';
						}
					}
					$effective_filters['start_datetime'] = $start_datetime->format('Y-m-d H:i:s T');
					$effective_filters['end_datetime'] = $end_datetime->format('Y-m-d H:i:s T');
				}
			}

			if ($start_datetime instanceof DateTime && $end_datetime instanceof DateTime) {
				if (($end_datetime->getTimestamp() - $start_datetime->getTimestamp()) > 86400) {
					$warnings[] = 'Broad searches may affect server performance. Consider narrowing the search criteria.';
				}
			}
			else {
				$warnings[] = 'Broad searches may affect server performance. Consider narrowing the search criteria.';
			}

			if (!empty($errors)) {
				return [
					'matched_count' => 0,
					'effective_filters' => $effective_filters,
					'max_records' => $max_records,
					'warnings' => $warnings,
					'errors' => $errors,
				];
			}

			$sql = "select count(*) as count from v_xml_cdr where true ";
			$parameters = [];
			if (!$all_domains_allowed) {
				$sql .= "and domain_uuid = :domain_uuid ";
				$parameters['domain_uuid'] = $effective_filters['domain_uuid'];
			}
			if ($call_uuid !== '') {
				$sql .= "and (xml_cdr_uuid = :call_uuid or bridge_uuid = :call_uuid or originating_leg_uuid = :call_uuid) ";
				$parameters['call_uuid'] = $call_uuid;
			}
			if ($start_datetime instanceof DateTime && $end_datetime instanceof DateTime) {
				$sql .= "and start_stamp between :start_stamp_begin and :start_stamp_end ";
				$parameters['start_stamp_begin'] = $start_datetime->format('c');
				$parameters['start_stamp_end'] = $end_datetime->format('c');
			}
			if ($effective_filters['destination_number'] !== '') {
				$sql .= "and (lower(coalesce(destination_number, '')) like :destination_like or lower(coalesce(caller_destination, '')) like :destination_like) ";
				$parameters['destination_like'] = '%'.strtolower($effective_filters['destination_number']).'%';
			}
			if ($effective_filters['caller_id'] !== '') {
				$sql .= "and (lower(coalesce(caller_id_number, '')) like :caller_like or lower(coalesce(source_number, '')) like :caller_like or lower(coalesce(caller_id_name, '')) like :caller_like) ";
				$parameters['caller_like'] = '%'.strtolower($effective_filters['caller_id']).'%';
			}
			if ($effective_filters['extension'] !== '') {
				$sql .= "and (lower(coalesce(caller_destination, '')) like :extension_like or lower(coalesce(destination_number, '')) like :extension_like or lower(coalesce(source_number, '')) like :extension_like or lower(coalesce(caller_id_number, '')) like :extension_like) ";
				$parameters['extension_like'] = '%'.strtolower($effective_filters['extension']).'%';
			}

			try {
				$count = (int) $database->select($sql, $parameters, 'column');
			}
			catch (Throwable $e) {
				return [
					'matched_count' => 0,
					'effective_filters' => $effective_filters,
					'max_records' => $max_records,
					'warnings' => $warnings,
					'errors' => ['CDR match count query failed.'],
				];
			}

			if ($count > $max_records) {
				$warnings[] = 'Matched count exceeds max records limit.';
			}

			return [
				'matched_count' => $count,
				'effective_filters' => $effective_filters,
				'max_records' => $max_records,
				'warnings' => $warnings,
				'errors' => [],
			];
		}

		/**
		 * Collect bounded preview CDR records for the detailed CDR preview UI.
		 *
		 * @param array $filters
		 * @return array
		 */
		public function collect_cdr_preview_records($filters = []) {
			global $database;

			$match = $this->collect_cdr_detailed_match_count($filters);
			$effective_filters = is_array($match['effective_filters'] ?? null) ? $match['effective_filters'] : [];
			$max_records = isset($match['max_records']) ? (int) $match['max_records'] : 25;
			if ($max_records < 1) {
				$max_records = 25;
			}
			if ($max_records > 100) {
				$max_records = 100;
			}

			if (!empty($match['errors'])) {
				return [
					'records' => [],
					'effective_filters' => $effective_filters,
					'max_records' => $max_records,
					'warnings' => $match['warnings'] ?? [],
					'errors' => $match['errors'] ?? [],
				];
			}

			if (!is_object($database)) {
				return [
					'records' => [],
					'effective_filters' => $effective_filters,
					'max_records' => $max_records,
					'warnings' => $match['warnings'] ?? [],
					'errors' => ['database connection unavailable.'],
				];
			}

			$all_domains_allowed = (($effective_filters['scope'] ?? 'current domain') === 'all domains');
			$sql = "select
					start_stamp,
					direction,
					caller_id_name,
					caller_id_number,
					destination_number,
					billsec,
					duration,
					sip_hangup_disposition,
					hangup_cause,
					domain_uuid,
					xml_cdr_uuid,
					record_name,
					record_path
				from v_xml_cdr
				where true ";
			$parameters = [];

			if (!$all_domains_allowed) {
				$sql .= "and domain_uuid = :domain_uuid ";
				$parameters['domain_uuid'] = $effective_filters['domain_uuid'] ?? null;
			}

			$call_uuid = trim((string) ($effective_filters['call_uuid'] ?? ''));
			if ($call_uuid !== '') {
				$sql .= "and (xml_cdr_uuid = :call_uuid or bridge_uuid = :call_uuid or originating_leg_uuid = :call_uuid) ";
				$parameters['call_uuid'] = $call_uuid;
			}

			$start_datetime_raw = trim((string) ($effective_filters['start_datetime'] ?? ''));
			$end_datetime_raw = trim((string) ($effective_filters['end_datetime'] ?? ''));
			if ($start_datetime_raw !== '' && $end_datetime_raw !== '') {
				$start_datetime = DateTime::createFromFormat('Y-m-d H:i:s T', $start_datetime_raw);
				$end_datetime = DateTime::createFromFormat('Y-m-d H:i:s T', $end_datetime_raw);
				if ($start_datetime instanceof DateTime && $end_datetime instanceof DateTime) {
					$sql .= "and start_stamp between :start_stamp_begin and :start_stamp_end ";
					$parameters['start_stamp_begin'] = $start_datetime->format('c');
					$parameters['start_stamp_end'] = $end_datetime->format('c');
				}
			}

			$destination_number = trim((string) ($effective_filters['destination_number'] ?? ''));
			if ($destination_number !== '') {
				$sql .= "and (lower(coalesce(destination_number, '')) like :destination_like or lower(coalesce(caller_destination, '')) like :destination_like) ";
				$parameters['destination_like'] = '%'.strtolower($destination_number).'%';
			}

			$caller_id = trim((string) ($effective_filters['caller_id'] ?? ''));
			if ($caller_id !== '') {
				$sql .= "and (lower(coalesce(caller_id_number, '')) like :caller_like or lower(coalesce(source_number, '')) like :caller_like or lower(coalesce(caller_id_name, '')) like :caller_like) ";
				$parameters['caller_like'] = '%'.strtolower($caller_id).'%';
			}

			$extension = trim((string) ($effective_filters['extension'] ?? ''));
			if ($extension !== '') {
				$sql .= "and (lower(coalesce(caller_destination, '')) like :extension_like or lower(coalesce(destination_number, '')) like :extension_like or lower(coalesce(source_number, '')) like :extension_like or lower(coalesce(caller_id_number, '')) like :extension_like) ";
				$parameters['extension_like'] = '%'.strtolower($extension).'%';
			}

			$sql .= "order by start_stamp desc limit :max_records";
			$parameters['max_records'] = $max_records;

			try {
				$rows = $database->select($sql, $parameters, 'all');
			}
			catch (Throwable $e) {
				return [
					'records' => [],
					'effective_filters' => $effective_filters,
					'max_records' => $max_records,
					'warnings' => $match['warnings'] ?? [],
					'errors' => ['CDR preview query failed.'],
				];
			}

			$records = [];
			if (is_array($rows)) {
				foreach ($rows as $row) {
					$duration = $row['billsec'] ?? null;
					if ($duration === null || $duration === '') {
						$duration = $row['duration'] ?? '';
					}
					$records[] = [
						'start_time' => (string) ($row['start_stamp'] ?? ''),
						'direction' => (string) ($row['direction'] ?? ''),
						'caller_id_name' => (string) ($row['caller_id_name'] ?? ''),
						'caller_id_number' => (string) ($row['caller_id_number'] ?? ''),
						'destination' => (string) ($row['destination_number'] ?? ''),
						'duration' => (string) $duration,
						'status' => (string) ($row['sip_hangup_disposition'] ?? ''),
						'hangup_cause' => (string) ($row['hangup_cause'] ?? ''),
					'domain_uuid' => (string) ($row['domain_uuid'] ?? ''),
						'call_uuid' => (string) ($row['xml_cdr_uuid'] ?? ''),
						'recording_present' => (!empty($row['record_name']) || !empty($row['record_path'])),
					];
				}
			}

			return [
				'records' => $records,
				'effective_filters' => $effective_filters,
				'max_records' => $max_records,
				'warnings' => $match['warnings'] ?? [],
				'errors' => [],
			];
		}


		/**
		 * Collect bounded selected-call CDR evidence sections for bundle export.
		 *
		 * @param array $filters
		 * @param array $options
		 * @return array
		 */
		public function collect_cdr_selected_evidence_sections($filters = [], $options = []) {
			global $database;

			$warnings = [];
			$errors = [];
			$filters = is_array($filters) ? $filters : [];

			if (!permission_exists('diagnostics_collect')) {
				$errors[] = 'diagnostics_collect permission required.';
			}
			if (!permission_exists('diagnostics_download')) {
				$errors[] = 'diagnostics_download permission required.';
			}
			if (!permission_exists('xml_cdr_view')) {
				$errors[] = 'xml_cdr_view permission required.';
			}
			if (!is_object($database)) {
				$errors[] = 'database connection unavailable.';
			}

			$include_logs_requested = !empty($filters['include_logs']);
			$filters['include_logs'] = false;
			if ($include_logs_requested) {
				$warnings[] = 'Include Logs is inactive in Phase 1A and was ignored.';
			}

			$match = $this->collect_cdr_detailed_match_count($filters);
			$preview = $this->collect_cdr_preview_records($filters);
			$warnings = array_values(array_unique(array_merge(
				$warnings,
				is_array($match['warnings'] ?? null) ? $match['warnings'] : [],
				is_array($preview['warnings'] ?? null) ? $preview['warnings'] : []
			)));
			$errors = array_values(array_unique(array_merge(
				$errors,
				is_array($match['errors'] ?? null) ? $match['errors'] : [],
				is_array($preview['errors'] ?? null) ? $preview['errors'] : []
			)));

			$matched_count = (int) ($match['matched_count'] ?? 0);
			$max_records = (int) ($match['max_records'] ?? 25);
			$effective_filters = is_array($match['effective_filters'] ?? null) ? $match['effective_filters'] : [];
			$selected_preview_rows = is_array($preview['records'] ?? null) ? $preview['records'] : [];

			$prior_preview_matched_count = null;
			if (isset($options['prior_preview_matched_count']) && $options['prior_preview_matched_count'] !== '') {
				$prior_preview_matched_count = (int) $options['prior_preview_matched_count'];
				if ($prior_preview_matched_count !== $matched_count) {
					$warnings[] = 'Current matched count differs from the prior preview count.';
				}
			}

			$prior_preview_selected_count = null;
			if (isset($options['prior_preview_selected_count']) && $options['prior_preview_selected_count'] !== '') {
				$prior_preview_selected_count = (int) $options['prior_preview_selected_count'];
				if ($prior_preview_selected_count !== count($selected_preview_rows)) {
					$warnings[] = 'Current selected call count differs from the prior preview count.';
				}
			}

			$selected_call_uuids = [];
			foreach ($selected_preview_rows as $selected_preview_row) {
				$call_uuid = trim((string) ($selected_preview_row['call_uuid'] ?? ''));
				if ($this->is_valid_uuid($call_uuid) && !in_array($call_uuid, $selected_call_uuids, true)) {
					$selected_call_uuids[] = $call_uuid;
				}
			}

			$selected_rows_by_uuid = [];
			$flow_rows_by_uuid = [];
			$queue_rows_by_uuid = [];
			$transcript_rows_by_uuid = [];
			if (empty($errors) && !empty($selected_call_uuids)) {
				$parameters = [];
				$in_clause = $this->build_in_clause($selected_call_uuids, 'cdr_uuid', $parameters);
				try {
					$sql = "select * from v_xml_cdr where xml_cdr_uuid in (".$in_clause.")";
					$selected_rows = $database->select($sql, $parameters, 'all');
					if (is_array($selected_rows)) {
						foreach ($selected_rows as $selected_row) {
							$row_uuid = trim((string) ($selected_row['xml_cdr_uuid'] ?? ''));
							if ($row_uuid !== '') {
								$selected_rows_by_uuid[$row_uuid] = $selected_row;
							}
						}
					}
				}
				catch (Throwable $e) {
					$errors[] = 'Selected call lookup query failed.';
				}

				$parameters = [];
				$in_clause = $this->build_in_clause($selected_call_uuids, 'flow_uuid', $parameters);
				try {
					$sql = "select xml_cdr_uuid, call_flow from v_xml_cdr_flow where xml_cdr_uuid in (".$in_clause.")";
					$flow_rows = $database->select($sql, $parameters, 'all');
					if (is_array($flow_rows)) {
						foreach ($flow_rows as $flow_row) {
							$row_uuid = trim((string) ($flow_row['xml_cdr_uuid'] ?? ''));
							if ($row_uuid !== '' && !array_key_exists($row_uuid, $flow_rows_by_uuid)) {
								$flow_rows_by_uuid[$row_uuid] = $flow_row['call_flow'] ?? null;
							}
						}
					}
				}
				catch (Throwable $e) {
					$warnings[] = 'v_xml_cdr_flow query unavailable; flow metadata was skipped.';
				}

				$parameters = [];
				$in_clause = $this->build_in_clause($selected_call_uuids, 'queue_uuid', $parameters);
				try {
					$sql = "select transcribe_queue_uuid, transcribe_status, transcribe_duration, hostname, transcribe_audio_path, transcribe_audio_name ";
					$sql .= "from v_transcribe_queue where transcribe_queue_uuid in (".$in_clause.")";
					$queue_rows = $database->select($sql, $parameters, 'all');
					if (is_array($queue_rows)) {
						foreach ($queue_rows as $queue_row) {
							$row_uuid = trim((string) ($queue_row['transcribe_queue_uuid'] ?? ''));
							if ($row_uuid !== '' && !array_key_exists($row_uuid, $queue_rows_by_uuid)) {
								$queue_rows_by_uuid[$row_uuid] = $queue_row;
							}
						}
					}
				}
				catch (Throwable $e) {
					$warnings[] = 'v_transcribe_queue query unavailable; transcript queue metadata was skipped.';
				}

				$parameters = [];
				$in_clause = $this->build_in_clause($selected_call_uuids, 'transcript_uuid', $parameters);
				try {
					$sql = "select xml_cdr_uuid, transcript_json, transcript_summary from v_xml_cdr_transcripts ";
					$sql .= "where xml_cdr_uuid in (".$in_clause.")";
					$transcript_rows = $database->select($sql, $parameters, 'all');
					if (is_array($transcript_rows)) {
						foreach ($transcript_rows as $transcript_row) {
							$row_uuid = trim((string) ($transcript_row['xml_cdr_uuid'] ?? ''));
							if ($row_uuid !== '' && !array_key_exists($row_uuid, $transcript_rows_by_uuid)) {
								$transcript_rows_by_uuid[$row_uuid] = $transcript_row;
							}
						}
					}
				}
				catch (Throwable $e) {
					$warnings[] = 'v_xml_cdr_transcripts query unavailable; transcript metadata was skipped.';
				}
			}

			$selected_calls = [];
			$calls_warnings = [];
			foreach ($selected_call_uuids as $selected_call_uuid) {
				$selected_row = $selected_rows_by_uuid[$selected_call_uuid] ?? [];
				if (empty($selected_row)) {
					$calls_warnings[] = 'No v_xml_cdr row was found for one or more selected UUIDs.';
				}

				$flow_value = $flow_rows_by_uuid[$selected_call_uuid] ?? null;
				$flow_metadata = $this->flow_metadata($flow_value);
				$recording_metadata = $this->recording_metadata($selected_row);
				if (!empty($recording_metadata['warnings'])) {
					$calls_warnings = array_merge($calls_warnings, $recording_metadata['warnings']);
				}
				$transcript_metadata = $this->transcript_metadata(
					$selected_call_uuid,
					$queue_rows_by_uuid[$selected_call_uuid] ?? null,
					$transcript_rows_by_uuid[$selected_call_uuid] ?? null
				);
				$provenance_metadata = $this->cdr_provenance_metadata($selected_call_uuid, $selected_row);
				if (!empty($provenance_metadata['warnings'])) {
					$calls_warnings = array_merge($calls_warnings, $provenance_metadata['warnings']);
				}
				$failed_import_metadata = $this->failed_import_artifact_metadata($selected_call_uuid);

				$selected_calls[] = [
					'xml_cdr_uuid' => $selected_call_uuid,
					'v_xml_cdr' => $this->sanitize_cdr_row($selected_row),
					'v_xml_cdr_flow' => $flow_metadata,
					'recording_metadata' => $recording_metadata['metadata'],
					'transcript_metadata' => $transcript_metadata,
					'raw_cdr_provenance' => $provenance_metadata['metadata'],
					'failed_import_artifacts' => $failed_import_metadata,
				];
			}
			$calls_warnings = array_values(array_unique($calls_warnings));
			$warnings = array_values(array_unique($warnings));

			$collection_policy = [
				'status' => empty($errors) ? 'collected' : 'error',
				'scope' => 'bounded selected calls',
				'record_count' => count($selected_call_uuids),
				'warnings' => $warnings,
				'errors' => $errors,
				'phase' => '1A',
				'included' => [
					'v_xml_cdr operational row (non-secret fields only)',
					'v_xml_cdr_flow call_flow metadata when present',
					'recording metadata only',
					'transcript metadata only',
					'raw CDR provenance metadata only',
					'failed-import artifact metadata when safely associated',
				],
				'excluded' => [
					'recording audio',
					'waveform output',
					'call_recording_base64',
					'transcript_json body',
					'transcript_summary text',
					'raw xml/json CDR body',
					'cdr log content',
					'passwords',
					'sip credentials',
					'tokens',
					'api keys',
					'unrelated freeswitch logs',
				],
				'enforcement' => [
					'search_revalidated_server_side' => true,
					'posted_preview_rows_trusted' => false,
					'posted_uuid_lists_trusted' => false,
					'posted_browser_counts_trusted' => false,
					'include_logs_active' => false,
				],
			];

			$call_index = [
				'status' => empty($errors) ? 'collected' : 'error',
				'scope' => 'bounded selected calls',
				'record_count' => count($selected_call_uuids),
				'warnings' => $warnings,
				'errors' => $errors,
				'matched_count' => $matched_count,
				'selected_count' => count($selected_call_uuids),
				'max_records' => $max_records,
				'effective_filters' => $effective_filters,
				'prior_preview' => [
					'matched_count' => $prior_preview_matched_count,
					'selected_count' => $prior_preview_selected_count,
				],
				'call_uuids' => $selected_call_uuids,
			];

			$calls_section = [
				'status' => empty($errors) ? 'collected' : 'error',
				'scope' => 'bounded selected calls',
				'record_count' => count($selected_calls),
				'warnings' => $calls_warnings,
				'errors' => $errors,
				'calls' => $selected_calls,
			];

			return [
				'collection_policy' => $collection_policy,
				'call_index' => $call_index,
				'selected_calls' => $calls_section,
				'matched_count' => $matched_count,
				'selected_count' => count($selected_call_uuids),
				'effective_filters' => $effective_filters,
				'warnings' => $warnings,
				'errors' => $errors,
			];
		}

		/**
		 * Collect a safe, read-only system information preview.
		 *
		 * @return array
		 */
		public function collect_system_preview() {
			global $config, $db_type;

			$warnings = [];

			$fusionpbx_version = null;
			if (class_exists('software') && method_exists('software', 'version')) {
				$fusionpbx_version = software::version();
			}
			$this->warn_if_empty($warnings, 'fusionpbx_version', $fusionpbx_version);

			$database_type = $db_type ?? null;
			$this->warn_if_empty($warnings, 'database_type', $database_type);

			$database_driver = is_object($config) ? $config->get('database.0.driver') : null;
			$database_driver = !empty($database_driver) ? $database_driver : $database_type;
			$this->warn_if_empty($warnings, 'database_driver', $database_driver);

			$domain_uuid = $_SESSION['domain_uuid'] ?? null;
			$domain_name = $_SESSION['domain_name'] ?? null;
			$user_uuid = $_SESSION['user_uuid'] ?? null;
			$this->warn_if_empty($warnings, 'domain_uuid', $domain_uuid);
			$this->warn_if_empty($warnings, 'domain_name', $domain_name);
			$this->warn_if_empty($warnings, 'user_uuid', $user_uuid);

			return [
				'status' => 'collected',
				'collector_version' => self::COLLECTOR_VERSION,
				'schema_version' => self::SCHEMA_VERSION,
				'generated_at' => gmdate('c'),
				'fusionpbx' => [
					'version' => $fusionpbx_version,
					'php_version' => PHP_VERSION,
					'database_type' => $database_type,
					'database_driver' => $database_driver,
				],
				'current_domain' => [
					'domain_uuid' => $domain_uuid,
					'domain_name' => $domain_name,
				],
				'current_user' => [
					'user_uuid' => $user_uuid,
				],
				'permissions' => $this->diagnostics_permissions(),
				'warnings' => $warnings,
			];
		}


		/**
		 * Collect a redacted, read-only domains preview.
		 *
		 * @return array
		 */
		public function collect_domains_preview() {
			global $database;

			$warnings = [];
			$scope = permission_exists('domain_all') ? 'all domains' : 'current domain';

			if (!permission_exists('domain_view')) {
				return [
					'status' => 'permission_denied',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['domain_view permission required'],
					'data' => [],
				];
			}

			if (!is_object($database)) {
				return [
					'status' => 'unavailable',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['database connection unavailable'],
					'data' => [],
				];
			}

			$sql = "select domain_uuid, domain_name, cast(domain_enabled as text) as domain_enabled ";
			$sql .= "from v_domains ";
			$parameters = null;
			if (!permission_exists('domain_all')) {
				$domain_uuid = $_SESSION['domain_uuid'] ?? null;
				if (empty($domain_uuid)) {
					return [
						'status' => 'unavailable',
						'scope' => $scope,
						'record_count' => 0,
						'warnings' => ['current domain_uuid unavailable'],
						'data' => [],
					];
				}
				$sql .= "where domain_uuid = :domain_uuid ";
				$parameters['domain_uuid'] = $domain_uuid;
			}
			$sql .= "order by domain_uuid asc ";

			try {
				$rows = $database->select($sql, $parameters, 'all');
			}
			catch (Throwable $e) {
				return [
					'status' => 'error',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['domains query failed'],
					'data' => [],
				];
			}

			$data = [];
			if (!empty($rows) && is_array($rows)) {
				foreach ($rows as $row) {
					$data[] = [
						'domain_uuid' => $row['domain_uuid'] ?? null,
						'domain_name' => $row['domain_name'] ?? null,
						'domain_enabled' => $row['domain_enabled'] ?? null,
					];
				}
			}

			if (empty($data)) {
				$warnings[] = 'no domains found for scope';
			}

			return [
				'status' => 'collected',
				'scope' => $scope,
				'record_count' => count($data),
				'warnings' => $warnings,
				'data' => $data,
			];
		}


		/**
		 * Collect a redacted, read-only extensions preview.
		 *
		 * @return array
		 */
		public function collect_extensions_preview() {
			global $database;

			$warnings = [];
			$scope = permission_exists('extension_all') ? 'all domains' : 'current domain';

			if (!permission_exists('extension_view')) {
				return [
					'status' => 'permission_denied',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['extension_view permission required'],
					'data' => [],
				];
			}

			if (!is_object($database)) {
				return [
					'status' => 'unavailable',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['database connection unavailable'],
					'data' => [],
				];
			}

			$sql = "select extension_uuid, domain_uuid, extension, number_alias, cast(enabled as text) as enabled, ";
			$sql .= "cast(directory_visible as text) as directory_visible, ";
			$sql .= "cast(do_not_disturb as text) as do_not_disturb, user_context ";
			$sql .= "from v_extensions ";
			$parameters = null;
			if (!permission_exists('extension_all')) {
				$domain_uuid = $_SESSION['domain_uuid'] ?? null;
				if (empty($domain_uuid)) {
					return [
						'status' => 'unavailable',
						'scope' => $scope,
						'record_count' => 0,
						'warnings' => ['current domain_uuid unavailable'],
						'data' => [],
					];
				}
				$sql .= "where domain_uuid = :domain_uuid ";
				$parameters['domain_uuid'] = $domain_uuid;
			}
			$sql .= "order by extension_uuid asc ";

			try {
				$rows = $database->select($sql, $parameters, 'all');
			}
			catch (Throwable $e) {
				return [
					'status' => 'error',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['extensions query failed'],
					'data' => [],
				];
			}

			$data = [];
			if (!empty($rows) && is_array($rows)) {
				foreach ($rows as $row) {
					$data[] = [
						'extension_uuid' => $row['extension_uuid'] ?? null,
						'domain_uuid' => $row['domain_uuid'] ?? null,
						'extension' => $row['extension'] ?? null,
						'number_alias' => $row['number_alias'] ?? null,
						'enabled' => $row['enabled'] ?? null,
						'voicemail_enabled' => null,
						'directory_visible' => $row['directory_visible'] ?? null,
						'do_not_disturb' => $row['do_not_disturb'] ?? null,
						'user_context' => $row['user_context'] ?? null,
					];
				}
			}

			$warnings[] = 'voicemail_enabled unavailable from v_extensions';
			if (empty($data)) {
				$warnings[] = 'no extensions found for scope';
			}

			return [
				'status' => 'collected',
				'scope' => $scope,
				'record_count' => count($data),
				'warnings' => $warnings,
				'data' => $data,
			];
		}


		/**
		 * Collect a redacted, read-only gateways preview.
		 *
		 * @return array
		 */
		public function collect_gateways_preview() {
			global $database;

			$warnings = [];
			$scope = permission_exists('gateway_all') ? 'all domains' : 'current domain';

			if (!permission_exists('gateway_view')) {
				return [
					'status' => 'permission_denied',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['gateway_view permission required'],
					'data' => [],
				];
			}

			if (!is_object($database)) {
				return [
					'status' => 'unavailable',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['database connection unavailable'],
					'data' => [],
				];
			}

			$sql = "select gateway_uuid, domain_uuid, gateway, proxy, realm, from_domain, ";
			$sql .= "register_proxy, outbound_proxy, cast(enabled as text) as enabled, ";
			$sql .= "cast(register as text) as register, register_transport, profile ";
			$sql .= "from v_gateways ";
			$parameters = null;
			if (!permission_exists('gateway_all')) {
				$domain_uuid = $_SESSION['domain_uuid'] ?? null;
				if (empty($domain_uuid)) {
					return [
						'status' => 'unavailable',
						'scope' => $scope,
						'record_count' => 0,
						'warnings' => ['current domain_uuid unavailable'],
						'data' => [],
					];
				}
				$sql .= "where domain_uuid = :domain_uuid ";
				$parameters['domain_uuid'] = $domain_uuid;
			}
			$sql .= "order by gateway_uuid asc ";

			try {
				$rows = $database->select($sql, $parameters, 'all');
			}
			catch (Throwable $e) {
				return [
					'status' => 'error',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['gateways query failed'],
					'data' => [],
				];
			}

			$data = [];
			if (!empty($rows) && is_array($rows)) {
				foreach ($rows as $row) {
					$data[] = [
						'gateway_uuid' => $row['gateway_uuid'] ?? null,
						'domain_uuid' => $row['domain_uuid'] ?? null,
						'gateway' => $row['gateway'] ?? null,
						'proxy' => $row['proxy'] ?? null,
						'realm' => $row['realm'] ?? null,
						'from_domain' => $row['from_domain'] ?? null,
						'register_proxy' => $row['register_proxy'] ?? null,
						'outbound_proxy' => $row['outbound_proxy'] ?? null,
						'enabled' => $row['enabled'] ?? null,
						'register' => $row['register'] ?? null,
						'profile' => $row['profile'] ?? null,
						'transport' => $row['register_transport'] ?? null,
					];
				}
			}

			if (empty($data)) {
				$warnings[] = 'no gateways found for scope';
			}

			return [
				'status' => 'collected',
				'scope' => $scope,
				'record_count' => count($data),
				'warnings' => $warnings,
				'data' => $data,
			];
		}


		/**
		 * Collect a redacted, read-only access controls preview.
		 *
		 * @return array
		 */
		public function collect_access_controls_preview() {
			global $database;

			$warnings = [];
			$scope = 'global';

			if (!permission_exists('access_control_view') || !permission_exists('access_control_node_view')) {
				return [
					'status' => 'permission_denied',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['access_control_view and access_control_node_view permissions required'],
					'data' => [],
				];
			}

			if (!is_object($database)) {
				return [
					'status' => 'unavailable',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['database connection unavailable'],
					'data' => [],
				];
			}

			try {
				$sql = "select access_control_uuid, access_control_name, access_control_default, access_control_description ";
				$sql .= "from v_access_controls ";
				$sql .= "order by access_control_name asc, access_control_uuid asc ";
				$access_controls = $database->select($sql, null, 'all');

				$sql = "select access_control_node_uuid, access_control_uuid, node_type, node_cidr, node_description ";
				$sql .= "from v_access_control_nodes ";
				$sql .= "order by access_control_uuid asc, access_control_node_uuid asc ";
				$nodes = $database->select($sql, null, 'all');
			}
			catch (Throwable $e) {
				return [
					'status' => 'error',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['access controls query failed'],
					'data' => [],
				];
			}

			$nodes_by_access_control = [];
			if (!empty($nodes) && is_array($nodes)) {
				foreach ($nodes as $node) {
					$access_control_uuid = $node['access_control_uuid'] ?? '';
					$cidr = $this->cidr_type($node['node_cidr'] ?? '');
					$nodes_by_access_control[$access_control_uuid][] = [
						'access_control_node_uuid' => $node['access_control_node_uuid'] ?? null,
						'node_type' => $node['node_type'] ?? null,
						'node_cidr' => $node['node_cidr'] ?? null,
						'cidr_type' => $cidr,
						'node_description' => $node['node_description'] ?? null,
						'enabled' => null,
					];
				}
			}

			$data = [];
			if (!empty($access_controls) && is_array($access_controls)) {
				foreach ($access_controls as $row) {
					$access_control_uuid = $row['access_control_uuid'] ?? '';
					$acl_nodes = $nodes_by_access_control[$access_control_uuid] ?? [];
					$ipv4_count = 0;
					$ipv6_count = 0;
					foreach ($acl_nodes as $node) {
						if ($node['cidr_type'] === 'ipv4') {
							$ipv4_count++;
						}
						if ($node['cidr_type'] === 'ipv6') {
							$ipv6_count++;
						}
					}
					$data[] = [
						'access_control_uuid' => $access_control_uuid,
						'access_control_name' => $row['access_control_name'] ?? null,
						'description' => $row['access_control_description'] ?? null,
						'enabled' => null,
						'default_action' => $row['access_control_default'] ?? null,
						'node_count' => count($acl_nodes),
						'ipv4_node_count' => $ipv4_count,
						'ipv6_node_count' => $ipv6_count,
						'nodes' => $acl_nodes,
					];
				}
			}

			$warnings[] = 'enabled unavailable from v_access_controls';
			if (empty($data)) {
				$warnings[] = 'no access controls found';
			}

			return [
				'status' => 'collected',
				'scope' => $scope,
				'record_count' => count($data),
				'warnings' => $warnings,
				'data' => $data,
			];
		}


		/**
		 * Collect a support-useful, read-only destinations preview.
		 *
		 * @return array
		 */
		public function collect_destinations_preview() {
			global $database;

			$warnings = [];
			$scope = permission_exists('destination_all') ? 'all domains' : 'current domain';

			if (!permission_exists('destination_view')) {
				return [
					'status' => 'permission_denied',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['destination_view permission required'],
					'data' => [],
				];
			}

			if (!is_object($database)) {
				return [
					'status' => 'unavailable',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['database connection unavailable'],
					'data' => [],
				];
			}

			$sql = "select destination_uuid, domain_uuid, destination_number, destination_type, ";
			$sql .= "destination_context, destination_app, destination_data, destination_alternate_app, ";
			$sql .= "destination_alternate_data, destination_order, cast(destination_enabled as text) as destination_enabled ";
			$sql .= "from v_destinations ";
			$parameters = null;
			if (!permission_exists('destination_all')) {
				$domain_uuid = $_SESSION['domain_uuid'] ?? null;
				if (empty($domain_uuid)) {
					return [
						'status' => 'unavailable',
						'scope' => $scope,
						'record_count' => 0,
						'warnings' => ['current domain_uuid unavailable'],
						'data' => [],
					];
				}
				$sql .= "where domain_uuid = :domain_uuid ";
				$parameters['domain_uuid'] = $domain_uuid;
			}
			$sql .= "order by destination_order asc, destination_number asc, destination_uuid asc ";

			try {
				$rows = $database->select($sql, $parameters, 'all');
			}
			catch (Throwable $e) {
				return [
					'status' => 'error',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['destinations query failed'],
					'data' => [],
				];
			}

			$data = [];
			if (!empty($rows) && is_array($rows)) {
				foreach ($rows as $row) {
					$actions = [];
					if (!empty($row['destination_app']) || !empty($row['destination_data'])) {
						$actions[] = [
							'app' => $this->redact_true_secret($row['destination_app'] ?? '', 'destination_app'),
							'data' => $this->redact_true_secret($row['destination_data'] ?? '', 'destination_data'),
						];
					}
					if (!empty($row['destination_alternate_app']) || !empty($row['destination_alternate_data'])) {
						$actions[] = [
							'app' => $this->redact_true_secret($row['destination_alternate_app'] ?? '', 'destination_alternate_app'),
							'data' => $this->redact_true_secret($row['destination_alternate_data'] ?? '', 'destination_alternate_data'),
						];
					}
					$action_label = '-';
					if (!empty($actions)) {
						$action_label = $actions[0]['app'] ?: '-';
					}

					$data[] = [
						'destination_uuid' => $row['destination_uuid'] ?? null,
						'domain_uuid_hash' => $this->hash_value($row['domain_uuid'] ?? ''),
						'destination' => $this->redact_true_secret($row['destination_number'] ?? '', 'destination_number'),
						'enabled' => $row['destination_enabled'] ?? null,
						'type' => $this->redact_true_secret($row['destination_type'] ?? '', 'destination_type'),
						'context' => $this->redact_true_secret($row['destination_context'] ?? '', 'destination_context'),
						'action' => $action_label,
						'order' => $row['destination_order'] ?? null,
						'actions' => $actions,
					];
				}
			}

			if (empty($data)) {
				$warnings[] = 'no destinations found for scope';
			}

			return [
				'status' => 'collected',
				'scope' => $scope,
				'record_count' => count($data),
				'warnings' => $warnings,
				'data' => $data,
			];
		}


		/**
		 * Collect a support-useful, read-only SIP profiles preview.
		 *
		 * @return array
		 */
		public function collect_sip_profiles_preview() {
			global $database;

			$warnings = [];
			$scope = 'global';

			if (!permission_exists('sip_profile_view')) {
				return [
					'status' => 'permission_denied',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['sip_profile_view permission required'],
					'data' => [],
				];
			}

			if (!is_object($database)) {
				return [
					'status' => 'unavailable',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['database connection unavailable'],
					'data' => [],
				];
			}

			try {
				$sql = "select sip_profile_uuid, sip_profile_name, cast(sip_profile_enabled as text) as sip_profile_enabled ";
				$sql .= "from v_sip_profiles ";
				$sql .= "order by sip_profile_name asc, sip_profile_uuid asc ";
				$profiles = $database->select($sql, null, 'all');

				$sql = "select sip_profile_domain_uuid, sip_profile_uuid, sip_profile_domain_name, ";
				$sql .= "sip_profile_domain_alias, sip_profile_domain_parse ";
				$sql .= "from v_sip_profile_domains ";
				$sql .= "order by sip_profile_uuid asc, sip_profile_domain_name asc, sip_profile_domain_uuid asc ";
				$domains = $database->select($sql, null, 'all');

				$sql = "select sip_profile_setting_uuid, sip_profile_uuid, sip_profile_setting_name, ";
				$sql .= "sip_profile_setting_value, cast(sip_profile_setting_enabled as text) as sip_profile_setting_enabled ";
				$sql .= "from v_sip_profile_settings ";
				$sql .= "order by sip_profile_uuid asc, sip_profile_setting_name asc, sip_profile_setting_uuid asc ";
				$settings = $database->select($sql, null, 'all');
			}
			catch (Throwable $e) {
				return [
					'status' => 'error',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['SIP profiles query failed'],
					'data' => [],
				];
			}

			$domains_by_profile = [];
			if (!empty($domains) && is_array($domains)) {
				foreach ($domains as $domain) {
					$sip_profile_uuid = $domain['sip_profile_uuid'] ?? '';
					$domains_by_profile[$sip_profile_uuid][] = [
						'sip_profile_domain_uuid' => $domain['sip_profile_domain_uuid'] ?? null,
						'name' => $this->redact_true_secret($domain['sip_profile_domain_name'] ?? '', 'sip_profile_domain_name'),
						'alias' => $domain['sip_profile_domain_alias'] ?? null,
						'parse' => $domain['sip_profile_domain_parse'] ?? null,
					];
				}
			}

			$settings_by_profile = [];
			if (!empty($settings) && is_array($settings)) {
				foreach ($settings as $setting) {
					$sip_profile_uuid = $setting['sip_profile_uuid'] ?? '';
					$setting_name = $setting['sip_profile_setting_name'] ?? '';
					$settings_by_profile[$sip_profile_uuid][] = [
						'sip_profile_setting_uuid' => $setting['sip_profile_setting_uuid'] ?? null,
						'name' => $setting_name,
						'value' => $this->redact_sip_profile_setting($setting_name, $setting['sip_profile_setting_value'] ?? ''),
						'enabled' => $setting['sip_profile_setting_enabled'] ?? null,
					];
				}
			}

			$data = [];
			if (!empty($profiles) && is_array($profiles)) {
				foreach ($profiles as $profile) {
					$sip_profile_uuid = $profile['sip_profile_uuid'] ?? '';
					$profile_domains = $domains_by_profile[$sip_profile_uuid] ?? [];
					$profile_settings = $settings_by_profile[$sip_profile_uuid] ?? [];
					$data[] = [
						'sip_profile_uuid' => $sip_profile_uuid,
						'profile' => $this->redact_true_secret($profile['sip_profile_name'] ?? '', 'sip_profile_name'),
						'enabled' => $profile['sip_profile_enabled'] ?? null,
						'domain_count' => count($profile_domains),
						'setting_count' => count($profile_settings),
						'domains' => $profile_domains,
						'settings' => $profile_settings,
					];
				}
			}

			if (empty($data)) {
				$warnings[] = 'no SIP profiles found';
			}

			return [
				'status' => 'collected',
				'scope' => $scope,
				'record_count' => count($data),
				'warnings' => $warnings,
				'data' => $data,
			];
		}


		/**
		 * Collect a support-useful, read-only variables preview.
		 *
		 * @return array
		 */
		public function collect_variables_preview() {
			global $database;

			$warnings = [];
			$scope = 'global';

			if (!permission_exists('var_view')) {
				return [
					'status' => 'permission_denied',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['var_view permission required'],
					'data' => [],
				];
			}

			if (!is_object($database)) {
				return [
					'status' => 'unavailable',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['database connection unavailable'],
					'data' => [],
				];
			}

			$sql = "select var_uuid, var_category, var_name, var_value, var_order, ";
			$sql .= "cast(var_enabled as text) as var_enabled ";
			$sql .= "from v_vars ";
			$sql .= "order by var_category asc, var_order asc, var_name asc, var_uuid asc ";

			try {
				$rows = $database->select($sql, null, 'all');
			}
			catch (Throwable $e) {
				return [
					'status' => 'error',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['variables query failed'],
					'data' => [],
				];
			}

			$data = [];
			if (!empty($rows) && is_array($rows)) {
				foreach ($rows as $row) {
					$data[] = [
						'var_uuid' => $row['var_uuid'] ?? null,
						'category' => $this->redact_true_secret($row['var_category'] ?? '', 'var_category'),
						'name' => $this->redact_true_secret($row['var_name'] ?? '', 'var_name'),
						'value' => $this->redact_variable_value($row['var_category'] ?? '', $row['var_name'] ?? '', $row['var_value'] ?? ''),
						'enabled' => $row['var_enabled'] ?? null,
						'order' => $row['var_order'] ?? null,
					];
				}
			}

			if (empty($data)) {
				$warnings[] = 'no variables found';
			}

			return [
				'status' => 'collected',
				'scope' => $scope,
				'record_count' => count($data),
				'warnings' => $warnings,
				'data' => $data,
			];
		}


		/**
		 * Collect a support-useful, read-only SIP status preview.
		 *
		 * @return array
		 */
		public function collect_sip_status_preview() {
			global $database;

			$warnings = [];
			$scope = 'global';

			if (!(permission_exists('system_status_sofia_status') || permission_exists('system_status_sofia_status_profile'))) {
				return [
					'status' => 'permission_denied',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['system_status_sofia_status or system_status_sofia_status_profile permission required'],
					'data' => [],
				];
			}

			if (!is_object($database)) {
				return [
					'status' => 'unavailable',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['database connection unavailable'],
					'data' => [],
				];
			}

			try {
				$event_socket = event_socket::create();
				if (!$event_socket->is_connected()) {
					return [
						'status' => 'unavailable',
						'scope' => $scope,
						'record_count' => 0,
						'warnings' => ['event socket unavailable'],
						'data' => [],
					];
				}
			}
			catch (Throwable $e) {
				return [
					'status' => 'error',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['event socket connection failed'],
					'errors' => [$e->getMessage()],
					'data' => [],
				];
			}

			$gateway_lookup = [];
			try {
				$sql = "select g.domain_uuid, g.gateway, g.gateway_uuid, d.domain_name ";
				$sql .= "from v_gateways as g left outer join v_domains as d on d.domain_uuid = g.domain_uuid ";
				$gateways = $database->select($sql, null, 'all');
				if (!empty($gateways) && is_array($gateways)) {
					foreach ($gateways as $gateway) {
						$gateway_lookup[strtolower($gateway['gateway_uuid'] ?? '')] = $gateway;
					}
				}
			}
			catch (Throwable $e) {
				$warnings[] = 'gateway lookup unavailable';
			}

			$sip_profiles = [];
			try {
				$hostname = gethostname();
				$sql = "select sip_profile_uuid, sip_profile_name from v_sip_profiles ";
				$sql .= "where sip_profile_enabled = true ";
				$parameters = null;
				if (!empty($hostname)) {
					$sql .= "and (sip_profile_hostname = :sip_profile_hostname ";
					$sql .= "or sip_profile_hostname = '' ";
					$sql .= "or sip_profile_hostname is null) ";
					$parameters['sip_profile_hostname'] = $hostname;
				}
				$sql .= "order by sip_profile_name asc ";
				$rows = $database->select($sql, $parameters, 'all');
				if (!empty($rows) && is_array($rows)) {
					foreach ($rows as $row) {
						$sip_profiles[$row['sip_profile_name']] = $row['sip_profile_uuid'];
					}
				}
			}
			catch (Throwable $e) {
				$warnings[] = 'sip profile lookup unavailable';
			}

			$data = [];

			if (permission_exists('system_status_sofia_status')) {
				try {
					$xml_response = trim($event_socket->request('api sofia xmlstatus'));
					$xml = $this->simplexml_from_status($xml_response);
					if ($xml !== null) {
						if (!empty($xml->profile)) {
							foreach ($xml->profile as $row) {
								$data[] = [
									'type' => 'profile',
									'name' => $this->redact_true_secret((string) $row->name, 'profile'),
									'profile' => $this->redact_true_secret((string) $row->name, 'profile'),
									'status' => null,
									'state' => $this->redact_true_secret((string) $row->state, 'state'),
									'host_ip' => $this->redact_true_secret((string) $row->data, 'data'),
									'details' => $this->xml_element_to_array($row),
								];
							}
						}
						if (!empty($xml->alias)) {
							foreach ($xml->alias as $row) {
								$data[] = [
									'type' => $this->redact_true_secret((string) $row->type, 'type') ?: 'alias',
									'name' => $this->redact_true_secret((string) $row->name, 'name'),
									'profile' => null,
									'status' => null,
									'state' => $this->redact_true_secret((string) $row->state, 'state'),
									'host_ip' => $this->redact_true_secret((string) $row->data, 'data'),
									'details' => $this->xml_element_to_array($row),
								];
							}
						}
					}
				}
				catch (Throwable $e) {
					$warnings[] = 'sofia xmlstatus failed';
				}

				try {
					$xml_response = trim($event_socket->request('api sofia xmlstatus gateway'));
					$xml = $this->simplexml_from_status($xml_response);
					if ($xml !== null && !empty($xml->gateway)) {
						foreach ($xml->gateway as $row) {
							$gateway_key = strtolower((string) $row->name);
							$gateway = $gateway_lookup[$gateway_key] ?? [];
							$gateway_name = $gateway['gateway'] ?? (string) $row->name;
							$domain_name = $gateway['domain_name'] ?? null;
							$data[] = [
								'type' => 'gateway',
								'name' => $this->redact_true_secret($gateway_name, 'gateway'),
								'domain' => $this->redact_true_secret($domain_name, 'domain'),
								'profile' => $this->redact_true_secret((string) $row->profile, 'profile'),
								'status' => $this->redact_true_secret((string) $row->status, 'status'),
								'state' => $this->redact_true_secret((string) $row->state, 'state'),
								'host_ip' => $this->redact_true_secret((string) $row->to, 'to'),
								'details' => $this->xml_element_to_array($row),
							];
						}
					}
				}
				catch (Throwable $e) {
					$warnings[] = 'sofia xmlstatus gateway failed';
				}
			}

			if (permission_exists('system_status_sofia_status_profile') && !empty($sip_profiles)) {
				foreach ($sip_profiles as $sip_profile_name => $sip_profile_uuid) {
					try {
						$xml_response = trim($event_socket->request('api sofia xmlstatus profile '.$sip_profile_name));
						$profile_state = $xml_response === 'Invalid Profile!' ? 'stopped' : 'running';
						if ($xml_response === 'Invalid Profile!') {
							$xml_response = '<error_msg>Invalid Profile!</error_msg>';
						}
						$xml = $this->simplexml_from_status($xml_response);
						$details = $xml !== null ? $this->xml_element_to_array($xml) : [];
						$profile_info = $details['profile_info'] ?? [];
						$data[] = [
							'type' => 'profile_detail',
							'name' => $this->redact_true_secret($sip_profile_name, 'profile'),
							'profile' => $this->redact_true_secret($sip_profile_name, 'profile'),
							'status' => $profile_state,
							'state' => $profile_state,
							'host_ip' => $this->first_non_empty([
								$profile_info['sip-ip'] ?? null,
								$profile_info['ext-sip-ip'] ?? null,
								$profile_info['url'] ?? null,
								$profile_info['bind-url'] ?? null,
							]),
							'details' => $this->redact_array_true_secrets($details),
						];
					}
					catch (Throwable $e) {
						$warnings[] = 'sofia xmlstatus profile '.$sip_profile_name.' failed';
					}
				}
			}

			if (empty($data)) {
				$warnings[] = 'no SIP status records returned';
			}

			return [
				'status' => 'collected',
				'scope' => $scope,
				'record_count' => count($data),
				'warnings' => $warnings,
				'data' => $data,
			];
		}


		/**
		 * Collect a support-useful, read-only registrations preview.
		 *
		 * @return array
		 */
		public function collect_registrations_preview() {
			$warnings = [];
			$scope = permission_exists('registration_all') ? 'all domains' : 'current domain';

			if (!(permission_exists('registration_view') || permission_exists('registration_domain') || permission_exists('registration_all'))) {
				return [
					'status' => 'permission_denied',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['registration_view permission required'],
					'data' => [],
				];
			}

			$registrations_class = dirname(__DIR__, 3).'/registrations/resources/classes/registrations.php';
			if (!file_exists($registrations_class)) {
				return [
					'status' => 'unavailable',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['registrations helper unavailable'],
					'data' => [],
				];
			}
			require_once $registrations_class;

			try {
				$registrations = new registrations;
				$registrations->show = permission_exists('registration_all') ? 'all' : 'local';
				$rows = $registrations->get('all');
			}
			catch (Throwable $e) {
				return [
					'status' => 'error',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['registrations query failed'],
					'errors' => [$e->getMessage()],
					'data' => [],
				];
			}

			$data = [];
			if (!empty($rows) && is_array($rows)) {
				foreach ($rows as $row) {
					$user = $this->redact_true_secret($row['user'] ?? '', 'user');
					$user_parts = explode('@', (string) ($row['user'] ?? ''), 2);
					$domain = $row['sip-auth-realm'] ?? ($user_parts[1] ?? null);
					$network_ip = $this->redact_true_secret($row['network-ip'] ?? '', 'network-ip');
					$network_port = $this->redact_true_secret($row['network-port'] ?? '', 'network-port');
					$data[] = [
						'user' => $user,
						'extension' => $this->redact_true_secret($user_parts[0] ?? '', 'extension'),
						'domain' => $this->redact_true_secret($domain, 'domain'),
						'profile' => $this->redact_true_secret($row['sip_profile_name'] ?? '', 'profile'),
						'user_agent' => $this->redact_true_secret($row['agent'] ?? '', 'agent'),
						'contact' => $this->redact_true_secret($row['contact'] ?? '', 'contact'),
						'network_ip' => $network_ip,
						'network_port' => $network_port,
						'network' => trim(($network_ip ?? '').(!empty($network_port) ? ':'.$network_port : '')),
						'host' => $this->redact_true_secret($row['host'] ?? '', 'host'),
						'lan_ip' => $this->redact_true_secret($row['lan-ip'] ?? '', 'lan-ip'),
						'status' => $this->redact_true_secret($row['status'] ?? '', 'status'),
						'ping_time' => $this->redact_true_secret($row['ping-time'] ?? '', 'ping-time'),
						'ping_status' => $this->redact_true_secret($row['ping-status'] ?? '', 'ping-status'),
					];
				}
			}

			if (empty($data)) {
				$warnings[] = 'no registrations returned for scope';
			}

			return [
				'status' => 'collected',
				'scope' => $scope,
				'record_count' => count($data),
				'warnings' => $warnings,
				'data' => $data,
			];
		}


		/**
		 * Collect a redacted, read-only dialplans preview.
		 *
		 * @return array
		 */
		public function collect_dialplans_preview() {
			global $database;

			$warnings = [];
			if (permission_exists('dialplan_all')) {
				$scope = 'all domains';
			}
			elseif (permission_exists('dialplan_global')) {
				$scope = 'current domain and global';
			}
			else {
				$scope = 'current domain';
			}

			if (!permission_exists('dialplan_view')) {
				return [
					'status' => 'permission_denied',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['dialplan_view permission required'],
					'data' => [],
				];
			}

			if (!is_object($database)) {
				return [
					'status' => 'unavailable',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['database connection unavailable'],
					'data' => [],
				];
			}

			$parameters = null;
			$where = '';
			if (!permission_exists('dialplan_all')) {
				$domain_uuid = $_SESSION['domain_uuid'] ?? null;
				if (empty($domain_uuid)) {
					return [
						'status' => 'unavailable',
						'scope' => $scope,
						'record_count' => 0,
						'warnings' => ['current domain_uuid unavailable'],
						'data' => [],
					];
				}
				if (permission_exists('dialplan_global')) {
					$where = "where (domain_uuid = :domain_uuid or domain_uuid is null or dialplan_context in ('global', 'public')) ";
				}
				else {
					$where = "where domain_uuid = :domain_uuid ";
				}
				$parameters['domain_uuid'] = $domain_uuid;
			}

			try {
				$sql = "select dialplan_uuid, domain_uuid, dialplan_name, dialplan_context, dialplan_order, ";
				$sql .= "cast(dialplan_enabled as text) as dialplan_enabled ";
				$sql .= "from v_dialplans ";
				$sql .= $where;
				$sql .= "order by dialplan_order asc, dialplan_uuid asc ";
				$dialplans = $database->select($sql, $parameters, 'all');

				$sql = "select d.dialplan_detail_uuid, d.dialplan_uuid, d.dialplan_detail_tag, ";
				$sql .= "d.dialplan_detail_type, d.dialplan_detail_data, d.dialplan_detail_order, ";
				$sql .= "cast(d.dialplan_detail_enabled as text) as dialplan_detail_enabled ";
				$sql .= "from v_dialplan_details as d ";
				$sql .= "inner join v_dialplans as p on p.dialplan_uuid = d.dialplan_uuid ";
				if (!permission_exists('dialplan_all')) {
					if (permission_exists('dialplan_global')) {
						$sql .= "where (p.domain_uuid = :domain_uuid or p.domain_uuid is null or p.dialplan_context in ('global', 'public')) ";
					}
					else {
						$sql .= "where p.domain_uuid = :domain_uuid ";
					}
				}
				$sql .= "order by d.dialplan_uuid asc, d.dialplan_detail_order asc, d.dialplan_detail_uuid asc ";
				$details = $database->select($sql, $parameters, 'all');
			}
			catch (Throwable $e) {
				return [
					'status' => 'error',
					'scope' => $scope,
					'record_count' => 0,
					'warnings' => ['dialplans query failed'],
					'data' => [],
				];
			}

			$details_by_dialplan = [];
			if (!empty($details) && is_array($details)) {
				foreach ($details as $detail) {
					$dialplan_uuid = $detail['dialplan_uuid'] ?? '';
					$details_by_dialplan[$dialplan_uuid][] = [
						'dialplan_detail_uuid' => $detail['dialplan_detail_uuid'] ?? null,
						'tag' => $detail['dialplan_detail_tag'] ?? null,
						'type' => $detail['dialplan_detail_type'] ?? null,
						'data' => $this->redact_dialplan_detail_data($detail['dialplan_detail_type'] ?? '', $detail['dialplan_detail_data'] ?? ''),
						'order' => $detail['dialplan_detail_order'] ?? null,
						'enabled' => $detail['dialplan_detail_enabled'] ?? null,
					];
				}
			}

			$data = [];
			if (!empty($dialplans) && is_array($dialplans)) {
				foreach ($dialplans as $row) {
					$dialplan_uuid = $row['dialplan_uuid'] ?? '';
					$dialplan_details = $details_by_dialplan[$dialplan_uuid] ?? [];
					$condition_count = 0;
					$action_count = 0;
					foreach ($dialplan_details as $detail) {
						if (in_array($detail['tag'], ['condition', 'regex'])) {
							$condition_count++;
						}
						if (in_array($detail['tag'], ['action', 'anti-action'])) {
							$action_count++;
						}
					}
					$data[] = [
						'dialplan_uuid' => $dialplan_uuid,
						'domain_uuid' => $row['domain_uuid'] ?? null,
						'dialplan_name' => $row['dialplan_name'] ?? null,
						'enabled' => $row['dialplan_enabled'] ?? null,
						'category' => null,
						'context' => $row['dialplan_context'] ?? null,
						'detail_count' => count($dialplan_details),
						'condition_count' => $condition_count,
						'action_count' => $action_count,
						'order' => $row['dialplan_order'] ?? null,
						'details' => $dialplan_details,
					];
				}
			}

			$warnings[] = 'category unavailable from v_dialplans';
			if (empty($data)) {
				$warnings[] = 'no dialplans found for scope';
			}

			return [
				'status' => 'collected',
				'scope' => $scope,
				'record_count' => count($data),
				'warnings' => $warnings,
				'data' => $data,
			];
		}

		/**
		 * Get diagnostics permission summary for the current user.
		 *
		 * @return array
		 */
		private function diagnostics_permissions() {
			$permissions = [
				'diagnostics_view',
				'diagnostics_collect',
				'diagnostics_download',
				'diagnostics_reports',
				'diagnostics_audit',
				'diagnostics_admin',
			];

			$summary = [];
			foreach ($permissions as $permission) {
				$summary[$permission] = permission_exists($permission);
			}
			return $summary;
		}


		/**
		 * Hash a sensitive value for preview output.
		 *
		 * @param string $value
		 * @return string|null
		 */
		private function hash_value($value) {
			if ($value === null || $value === '') {
				return null;
			}
			$salt = session_id() ?: 'diagnostics-preview';
			return hash_hmac('sha256', $value, $salt);
		}



		/**
		 * Redact true secret values while preserving support-useful identifiers.
		 *
		 * @param string $value
		 * @param string $field
		 * @return string|null
		 */
		private function redact_true_secret($value, $field = '') {
			$value = trim((string) $value);
			$field = strtolower((string) $field);
			if ($value === '') {
				return null;
			}

			$secret_patterns = [
				'password', 'passphrase', 'secret', 'token', 'api_key', 'apikey', 'private_key',
				'credential', 'auth_secret', 'database_password', 'event_socket_password', 'session_id',
			];
			foreach ($secret_patterns as $pattern) {
				if (strpos($field, $pattern) !== false) {
					return '[redacted]';
				}
			}
			foreach ($secret_patterns as $pattern) {
				$regex = '/(^|[^a-z0-9_])'.preg_quote($pattern, '/').'([^a-z0-9_]|$)/i';
				if (preg_match($regex, $value)) {
					return '[redacted]';
				}
			}

			return $value;
		}


		/**
		 * Redact true secret SIP profile setting values.
		 *
		 * @param string $name
		 * @param string $value
		 * @return string|null
		 */
		private function redact_sip_profile_setting($name, $value) {
			$name = strtolower((string) $name);
			$value = trim((string) $value);
			if ($value === '') {
				return null;
			}

			$secret_patterns = [
				'password', 'passphrase', 'secret', 'token', 'api-key', 'apikey', 'private-key',
				'private_key', 'key-file', 'key_file', 'credential', 'auth-secret', 'auth_secret',
			];
			foreach ($secret_patterns as $pattern) {
				if (strpos($name, $pattern) !== false) {
					return '[redacted]';
				}
			}
			if (preg_match('/(^|[^a-z0-9_])(password|passphrase|secret|token|api[_-]?key|private[_-]?key|credential|auth[_-]?secret)([^a-z0-9_]|$)/i', $value)) {
				return '[redacted]';
			}
			if (preg_match('/\.(key|pem)$/i', $value) && preg_match('/private|key/i', $name.$value)) {
				return '[redacted]';
			}

			return $value;
		}


		/**
		 * Redact true secret variable values while preserving operational values.
		 *
		 * @param string $category
		 * @param string $name
		 * @param string $value
		 * @return string|null
		 */
		private function redact_variable_value($category, $name, $value) {
			$category = strtolower((string) $category);
			$name = strtolower((string) $name);
			$value = trim((string) $value);
			if ($value === '') {
				return null;
			}

			$field = $category.' '.$name;
			$secret_patterns = [
				'password', 'passphrase', 'secret', 'token', 'api_key', 'apikey', 'api-key',
				'private_key', 'private-key', 'key_file', 'key-file', 'credential', 'credentials',
				'auth_secret', 'auth-secret', 'database_password', 'event_socket_password', 'session_id',
			];
			foreach ($secret_patterns as $pattern) {
				if (strpos($field, $pattern) !== false) {
					return '[redacted]';
				}
			}
			if (preg_match('/(^|[^a-z0-9_])(password|passphrase|secret|token|api[_-]?key|private[_-]?key|credential|credentials|auth[_-]?secret)([^a-z0-9_]|$)/i', $value)) {
				return '[redacted]';
			}
			if (preg_match('/\.(key|pem|p12|pfx)$/i', $value) && preg_match('/private|credential|key/i', $field.$value)) {
				return '[redacted]';
			}

			return $value;
		}


		/**
		 * Redact dialplan detail data while preserving diagnostic shape.
		 *
		 * @param string $type
		 * @param string $data
		 * @return string|null
		 */
		private function redact_dialplan_detail_data($type, $data) {
			$type = strtolower((string) $type);
			$data = trim((string) $data);
			if ($data === '') {
				return null;
			}

			$sensitive_patterns = [
				'password', 'passphrase', 'secret', 'token', 'api_key', 'apikey', 'api-key',
				'private_key', 'private-key', 'credential', 'credentials', 'auth_secret',
				'auth-secret', 'pin', 'database_password', 'event_socket_password',
			];
			foreach ($sensitive_patterns as $pattern) {
				if (strpos($type, $pattern) !== false || stripos($data, $pattern) !== false) {
					return '[redacted]';
				}
			}

			if (preg_match('/\.(key|pem|p12|pfx)(["\']|\s|$)/i', $data)) {
				return '[redacted]';
			}

			return $data;
		}

		/**
		 * Return a safe label for a dialplan context.
		 *
		 * @param string $context
		 * @return string|null
		 */
		private function safe_context_label($context) {
			$context = trim((string) $context);
			if ($context === '') {
				return null;
			}
			if (in_array($context, ['global', 'public', '${domain_name}'])) {
				return $context;
			}
			if (!empty($_SESSION['domain_name']) && $context === $_SESSION['domain_name']) {
				return 'current-domain';
			}
			return 'context-'.substr($this->hash_value($context), 0, 12);
		}

		/**
		 * Classify a CIDR or IP value while preserving the raw value elsewhere.
		 *
		 * @param string $value
		 * @return string
		 */
		private function cidr_type($value) {
			$value = trim((string) $value);
			if ($value === '') {
				return 'unknown';
			}

			$parts = explode('/', str_replace('\\', '/', $value), 2);
			$address = $parts[0] ?? '';
			if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
				return 'ipv4';
			}
			if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
				return 'ipv6';
			}

			return 'unknown';
		}


		/**
		 * Convert status XML text into a SimpleXMLElement.
		 *
		 * @param string $xml_response
		 * @return SimpleXMLElement|null
		 */
		private function simplexml_from_status($xml_response) {
			$xml_response = trim((string) $xml_response);
			if ($xml_response === '') {
				return null;
			}
			if (function_exists('iconv')) {
				$xml_response = iconv('utf-8', 'utf-8//IGNORE', $xml_response);
			}
			$xml_response = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $xml_response);
			$xml_response = str_replace('<profile-info>', '<profile_info>', $xml_response);
			$xml_response = str_replace('</profile-info>', '</profile_info>', $xml_response);
			return new SimpleXMLElement($xml_response);
		}

		/**
		 * Convert XML into an array without changing section-specific meaning.
		 *
		 * @param SimpleXMLElement $xml
		 * @return array
		 */
		private function xml_element_to_array($xml) {
			$array = json_decode(json_encode($xml), true);
			return is_array($array) ? $this->redact_array_true_secrets($array) : [];
		}

		/**
		 * Redact true secret values in nested arrays.
		 *
		 * @param mixed $value
		 * @param string $field
		 * @return mixed
		 */
		private function redact_array_true_secrets($value, $field = '') {
			if (is_array($value)) {
				$redacted = [];
				foreach ($value as $key => $item) {
					$redacted[$key] = $this->redact_array_true_secrets($item, (string) $key);
				}
				return $redacted;
			}
			return $this->redact_true_secret($value, $field);
		}

		/**
		 * Return the first non-empty value in a list.
		 *
		 * @param array $values
		 * @return string|null
		 */
		private function first_non_empty($values) {
			foreach ($values as $value) {
				$value = trim((string) $value);
				if ($value !== '') {
					return $this->redact_true_secret($value, 'host_ip');
				}
			}
			return null;
		}


		/**
		 * Add a warning when a safe preview field is unavailable.
		 *
		 * @param array $warnings
		 * @param string $field
		 * @param mixed $value
		 * @return void
		 */

		private function warn_if_empty(&$warnings, $field, $value) {
			if ($value === null || $value === '') {
				$warnings[] = $field.' unavailable';
			}
		}

		/**
		 * Build an IN-clause placeholder list and parameter map.
		 *
		 * @param array $values
		 * @param string $prefix
		 * @param array $parameters
		 * @return string
		 */
		private function build_in_clause($values, $prefix, &$parameters) {
			$values = is_array($values) ? array_values($values) : [];
			$placeholders = [];
			foreach ($values as $index => $value) {
				$key = $prefix.'_'.$index;
				$placeholders[] = ':'.$key;
				$parameters[$key] = (string) $value;
			}
			return !empty($placeholders) ? implode(', ', $placeholders) : "''";
		}

		/**
		 * Determine whether a value is a valid UUID.
		 *
		 * @param string $uuid
		 * @return bool
		 */
		private function is_valid_uuid($uuid) {
			$uuid = trim((string) $uuid);
			if ($uuid === '') {
				return false;
			}
			if (function_exists('is_uuid')) {
				return is_uuid($uuid);
			}
			return (bool) preg_match('/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i', $uuid);
		}

		/**
		 * Return a redacted operational CDR row.
		 *
		 * @param array $row
		 * @return array
		 */
		private function sanitize_cdr_row($row) {
			if (!is_array($row)) {
				return [];
			}

			$blocked_exact = [
				'xml',
				'json',
				'call_recording_base64',
				'transcript_json',
				'transcript_summary',
				'log_content',
			];
			$blocked_keywords = [
				'password',
				'secret',
				'token',
				'api_key',
				'apikey',
				'credential',
				'auth',
			];

			$sanitized = [];
			foreach ($row as $key => $value) {
				$key_name = strtolower((string) $key);
				if (in_array($key_name, $blocked_exact, true)) {
					continue;
				}
				$skip = false;
				foreach ($blocked_keywords as $blocked_keyword) {
					if (strpos($key_name, $blocked_keyword) !== false) {
						$skip = true;
						break;
					}
				}
				if ($skip) {
					continue;
				}
				if (is_array($value) || is_object($value)) {
					$encoded = json_encode($value, JSON_UNESCAPED_SLASHES);
					$sanitized[$key] = $encoded === false ? null : $encoded;
				}
				else {
					$sanitized[$key] = $value;
				}
			}
			return $sanitized;
		}

		/**
		 * Return call-flow metadata without exporting body content.
		 *
		 * @param mixed $flow_value
		 * @return array
		 */
		private function flow_metadata($flow_value) {
			$present = !($flow_value === null || $flow_value === '');
			$size_bytes = null;
			$sha256 = null;
			$json_valid = null;
			$call_flow = null;
			if ($present) {
				if (is_array($flow_value)) {
					$call_flow = $flow_value;
					$encoded = json_encode($flow_value, JSON_UNESCAPED_SLASHES);
					if ($encoded !== false) {
						$size_bytes = strlen($encoded);
						$sha256 = hash('sha256', $encoded);
						$json_valid = true;
					}
					else {
						$json_valid = false;
					}
				}
				elseif (is_object($flow_value)) {
					$encoded = json_encode($flow_value, JSON_UNESCAPED_SLASHES);
					if ($encoded !== false) {
						$size_bytes = strlen($encoded);
						$sha256 = hash('sha256', $encoded);
						$decoded = json_decode($encoded, true);
						$json_valid = json_last_error() === JSON_ERROR_NONE && is_array($decoded);
						if ($json_valid) {
							$call_flow = $decoded;
						}
					}
					else {
						$json_valid = false;
					}
				}
				else {
					$flow_string = (string) $flow_value;
					$size_bytes = strlen($flow_string);
					$sha256 = hash('sha256', $flow_string);
					$decoded = json_decode($flow_string, true);
					$json_valid = json_last_error() === JSON_ERROR_NONE && is_array($decoded);
					if ($json_valid) {
						$call_flow = $decoded;
					}
				}
			}
			return [
				'present' => $present,
				'size_bytes' => $size_bytes,
				'sha256' => $sha256,
				'json_valid' => $json_valid,
				'call_flow' => $call_flow,
			];
		}


		/**
		 * Build recording metadata while keeping file access bounded and safe.
		 *
		 * @param array $row
		 * @return array
		 */
		private function recording_metadata($row) {
			$warnings = [];
			$record_path = trim((string) ($row['record_path'] ?? ''));
			$record_name = trim((string) ($row['record_name'] ?? ''));
			$record_length = $row['record_length'] ?? null;
			$availability_state = 'unavailable';
			$file_exists = false;
			$size_bytes = null;
			$mtime = null;
			$extension = null;
			$mime_guess = null;

			if ($record_path === '' && $record_name === '') {
				$availability_state = 'not_recorded';
			}
			else {
				$path_valid = $record_path !== '' && strpos($record_path, "\0") === false && !preg_match('/^[a-z][a-z0-9+\-.]*:\/\//i', $record_path);
				$name_valid = $record_name !== ''
					&& strpos($record_name, "\0") === false
					&& strpos($record_name, '..') === false
					&& strpos($record_name, '/') === false
					&& strpos($record_name, '\\') === false
					&& !preg_match('/^[a-z][a-z0-9+\-.]*:\/\//i', $record_name);

				$file_path = null;
				if (!$path_valid || !$name_valid) {
					$availability_state = 'invalid_reference';
					$warnings[] = 'Recording metadata contains an invalid record path or filename.';
				}
				else {
					$file_path = rtrim($record_path, '/').'/'.$record_name;
					$file_exists = is_file($file_path);
					if ($file_exists) {
						$availability_state = 'available';
						$size_bytes = @filesize($file_path);
						$file_mtime = @filemtime($file_path);
						$mtime = $file_mtime ? gmdate('c', $file_mtime) : null;
						$extension = strtolower((string) pathinfo($record_name, PATHINFO_EXTENSION));
						if (function_exists('finfo_open') && is_readable($file_path)) {
							$finfo = @finfo_open(FILEINFO_MIME_TYPE);
							if ($finfo) {
								$mime_guess_result = @finfo_file($finfo, $file_path);
								if (is_string($mime_guess_result) && $mime_guess_result !== '') {
									$mime_guess = $mime_guess_result;
								}
								@finfo_close($finfo);
							}
						}
						if ($mime_guess === null && function_exists('mime_content_type') && is_readable($file_path)) {
							$mime_guess_result = @mime_content_type($file_path);
							if (is_string($mime_guess_result) && $mime_guess_result !== '') {
								$mime_guess = $mime_guess_result;
							}
						}
					}
					else {
						$availability_state = 'missing';
					}
				}
			}

			return [
				'warnings' => $warnings,
				'metadata' => [
					'record_path' => $record_path !== '' ? $record_path : null,
					'record_name' => $record_name !== '' ? $record_name : null,
					'record_length' => $record_length,
					'file_exists' => $file_exists,
					'size_bytes' => is_numeric($size_bytes) ? (int) $size_bytes : null,
					'mtime' => $mtime,
					'extension' => $extension,
					'mime_guess' => $mime_guess,
					'availability_state' => $availability_state,
					'warnings' => $warnings,
				],
			];
		}


		/**
		 * Build transcript metadata without including transcript body content.
		 *
		 * @param string $xml_cdr_uuid
		 * @param array|null $queue_row
		 * @param array|null $transcript_row
		 * @return array
		 */
		private function transcript_metadata($xml_cdr_uuid, $queue_row, $transcript_row) {
			$queue_row = is_array($queue_row) ? $queue_row : [];
			$transcript_row = is_array($transcript_row) ? $transcript_row : [];

			$queue_uuid = trim((string) ($queue_row['transcribe_queue_uuid'] ?? ''));
			$queue_present = $queue_uuid !== '';
			$queue_status = trim((string) ($queue_row['transcribe_status'] ?? ''));
			$duration_raw = $queue_row['transcribe_duration'] ?? null;
			$duration = is_numeric($duration_raw) ? (float) $duration_raw : null;
			$hostname = trim((string) ($queue_row['hostname'] ?? ''));
			$audio_path = trim((string) ($queue_row['transcribe_audio_path'] ?? ''));
			$audio_name = trim((string) ($queue_row['transcribe_audio_name'] ?? ''));

			$transcript_present = !empty($transcript_row);
			$transcript_json = $transcript_row['transcript_json'] ?? null;
			$json_valid = null;
			$segment_count = null;
			if ($transcript_present) {
				if (is_array($transcript_json)) {
					$json_valid = true;
					if (isset($transcript_json['segments']) && is_array($transcript_json['segments'])) {
						$segment_count = count($transcript_json['segments']);
					}
				}
				elseif (is_object($transcript_json)) {
					$encoded = json_encode($transcript_json, JSON_UNESCAPED_SLASHES);
					$decoded = $encoded === false ? null : json_decode($encoded, true);
					$json_valid = is_array($decoded);
					if (is_array($decoded) && isset($decoded['segments']) && is_array($decoded['segments'])) {
						$segment_count = count($decoded['segments']);
					}
				}
				else {
					$decoded = json_decode((string) $transcript_json, true);
					$json_valid = json_last_error() === JSON_ERROR_NONE && is_array($decoded);
					if ($json_valid && isset($decoded['segments']) && is_array($decoded['segments'])) {
						$segment_count = count($decoded['segments']);
					}
				}
			}

			$summary = $transcript_row['transcript_summary'] ?? null;
			$summary_present = is_string($summary) && trim($summary) !== '';
			$summary_length = $summary_present ? strlen((string) $summary) : 0;

			return [
				'requested' => $queue_present || $transcript_present,
				'queue_uuid' => $queue_present ? $queue_uuid : null,
				'queue_status' => $queue_status !== '' ? $queue_status : null,
				'duration' => $duration,
				'hostname' => $hostname !== '' ? $hostname : null,
				'audio_path' => $audio_path !== '' ? $audio_path : null,
				'audio_name' => $audio_name !== '' ? $audio_name : null,
				'transcript_row_present' => $transcript_present,
				'json_valid' => $json_valid,
				'segment_count' => $segment_count,
				'summary_present' => $summary_present,
				'summary_length' => $summary_length,
			];
		}

		/**
		 * Build raw CDR provenance metadata while excluding raw body content.
		 *
		 * @param string $xml_cdr_uuid
		 * @param array $row
		 * @return array
		 */
		private function cdr_provenance_metadata($xml_cdr_uuid, $row) {
			$warnings = [];
			$row = is_array($row) ? $row : [];
			$xml_value = $row['xml'] ?? null;
			$json_value = $row['json'] ?? null;
			$start_stamp_value = $row['start_stamp'] ?? null;
			$archive_files = [];

			$xml_meta = $this->body_provenance($xml_value, 'xml');
			$json_meta = $this->body_provenance($json_value, 'json');

			$start_stamp = null;
			if (!empty($start_stamp_value)) {
				try {
					$start_stamp = new DateTime((string) $start_stamp_value);
				}
				catch (Throwable $e) {
					$warnings[] = 'Unable to parse start_stamp for archive metadata lookup.';
				}
			}
			else {
				$warnings[] = 'start_stamp unavailable for archive metadata lookup.';
			}

			$xml_cdr_archive_base = $this->xml_cdr_archive_base_path();
			if ($start_stamp instanceof DateTime && $xml_cdr_archive_base !== null) {
				$year = $start_stamp->format('Y');
				$month = $start_stamp->format('M');
				$day = $start_stamp->format('d');
				$archive_dir = rtrim($xml_cdr_archive_base, '/').'/'.$year.'/'.$month.'/'.$day;
				$expected_files = [
					$archive_dir.'/'.$xml_cdr_uuid.'.xml' => 'xml',
					$archive_dir.'/'.$xml_cdr_uuid.'.json' => 'json',
				];
				foreach ($expected_files as $path => $format) {
					$archive_files[] = $this->archive_file_metadata($path, $format);
				}
			}
			elseif ($xml_cdr_archive_base === null) {
				$warnings[] = 'switch log path unavailable for archive metadata lookup.';
			}

			return [
				'warnings' => $warnings,
				'metadata' => [
					'db_xml' => $xml_meta,
					'db_json' => $json_meta,
					'archive_files' => $archive_files,
				],
			];
		}

		/**
		 * Build provenance metadata for a DB CDR body field.
		 *
		 * @param mixed $value
		 * @param string $format
		 * @return array
		 */
		private function body_provenance($value, $format) {
			$present = !($value === null || $value === '');
			$size_bytes = null;
			$sha256 = null;
			$parse_status = 'not_present';
			if ($present) {
				$body_string = null;
				if (is_array($value) || is_object($value)) {
					$body_string = json_encode($value, JSON_UNESCAPED_SLASHES);
				}
				else {
					$body_string = (string) $value;
				}
				if (is_string($body_string)) {
					$size_bytes = strlen($body_string);
					$sha256 = hash('sha256', $body_string);
					if ($format === 'xml') {
						$parse_status = @simplexml_load_string($body_string, 'SimpleXMLElement', LIBXML_NOCDATA) !== false ? 'valid' : 'invalid';
					}
					else {
						json_decode($body_string, true);
						$parse_status = json_last_error() === JSON_ERROR_NONE ? 'valid' : 'invalid';
					}
				}
				else {
					$parse_status = 'unavailable';
				}
			}
			return [
				'present' => $present,
				'size_bytes' => $size_bytes,
				'sha256' => $sha256,
				'parse_status' => $parse_status,
			];
		}

		/**
		 * Build archive file metadata for an expected UUID-based archive file.
		 *
		 * @param string $path
		 * @param string $format
		 * @return array
		 */
		private function archive_file_metadata($path, $format) {
			$exists = is_file($path);
			$size_bytes = $exists ? @filesize($path) : null;
			$file_mtime = $exists ? @filemtime($path) : null;
			$sha256 = ($exists && is_readable($path)) ? @hash_file('sha256', $path) : null;
			return [
				'format' => $format,
				'file_name' => basename($path),
				'present' => $exists,
				'size_bytes' => is_numeric($size_bytes) ? (int) $size_bytes : null,
				'mtime' => $file_mtime ? gmdate('c', $file_mtime) : null,
				'sha256' => is_string($sha256) && $sha256 !== '' ? $sha256 : null,
			];
		}

		/**
		 * Resolve the XML CDR archive base path from settings.
		 *
		 * @return string|null
		 */
		private function xml_cdr_archive_base_path() {
			if (!class_exists('settings')) {
				return '/var/log/freeswitch/xml_cdr/archive';
			}
			try {
				$settings = new settings;
				$switch_log = $settings->get('switch', 'log', '/var/log/freeswitch');
				$switch_log = trim((string) $switch_log);
				if ($switch_log === '') {
					return null;
				}
				return rtrim($switch_log, '/').'/xml_cdr/archive';
			}
			catch (Throwable $e) {
				return null;
			}
		}

		/**
		 * Build failed-import metadata using UUID-derived expected file names only.
		 *
		 * @param string $xml_cdr_uuid
		 * @return array
		 */
		private function failed_import_artifact_metadata($xml_cdr_uuid) {
			$xml_cdr_uuid = trim((string) $xml_cdr_uuid);
			$base_failed = $this->xml_cdr_failed_base_path();
			if ($xml_cdr_uuid === '' || $base_failed === null) {
				return [
					'present' => false,
					'artifacts' => [],
				];
			}

			$expected_names = [
				$xml_cdr_uuid.'.cdr.xml',
				'a_'.$xml_cdr_uuid.'.cdr.xml',
				$xml_cdr_uuid.'.cdr.json',
				'a_'.$xml_cdr_uuid.'.cdr.json',
				$xml_cdr_uuid.'.xml',
				$xml_cdr_uuid.'.json',
			];
			$failed_dirs = [
				'failed',
				'failed/xml',
				'failed/sql',
				'failed/size',
			];

			$artifacts = [];
			foreach ($failed_dirs as $failed_dir) {
				foreach ($expected_names as $expected_name) {
					$full_path = rtrim($base_failed, '/').'/'.$failed_dir.'/'.$expected_name;
					if (is_file($full_path)) {
						$size_bytes = @filesize($full_path);
						$file_mtime = @filemtime($full_path);
						$sha256 = is_readable($full_path) ? @hash_file('sha256', $full_path) : null;
						$artifacts[] = [
							'location' => $failed_dir.'/'.$expected_name,
							'present' => true,
							'size_bytes' => is_numeric($size_bytes) ? (int) $size_bytes : null,
							'mtime' => $file_mtime ? gmdate('c', $file_mtime) : null,
							'sha256' => is_string($sha256) && $sha256 !== '' ? $sha256 : null,
						];
					}
				}
			}

			return [
				'present' => !empty($artifacts),
				'artifacts' => $artifacts,
			];
		}

		/**
		 * Resolve the XML CDR failed-import base path from settings.
		 *
		 * @return string|null
		 */
		private function xml_cdr_failed_base_path() {
			if (!class_exists('settings')) {
				return '/var/log/freeswitch/xml_cdr';
			}
			try {
				$settings = new settings;
				$switch_log = $settings->get('switch', 'log', '/var/log/freeswitch');
				$switch_log = trim((string) $switch_log);
				if ($switch_log === '') {
					return null;
				}
				return rtrim($switch_log, '/').'/xml_cdr';
			}
			catch (Throwable $e) {
				return null;
			}
		}
	}

?>
