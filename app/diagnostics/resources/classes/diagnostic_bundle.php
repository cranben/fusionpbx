<?php

/**
 * diagnostic bundle
 */
	class diagnostic_bundle {

		/**
		 * Bundle writer version.
		 *
		 * @var string
		 */
		const MANIFEST_VERSION = '1.0.0';

		/**
		 * Stream a section-agnostic ZIP bundle to the browser.
		 *
		 * @param array $metadata
		 * @param array $sections
		 * @return void
		 */
		public function stream($metadata, $sections) {
			if (!class_exists('ZipArchive')) {
				throw new RuntimeException('ZipArchive is not available on this system.');
			}

			if (!is_array($sections)) {
				throw new RuntimeException('Diagnostic sections are unavailable.');
			}

			$collection_id = $metadata['collection_id'] ?? $this->create_uuid();
			$generated_at = $metadata['generated_at'] ?? gmdate('c');
			$schema_version = $metadata['schema_version'] ?? (defined('diagnostic_collector::SCHEMA_VERSION') ? diagnostic_collector::SCHEMA_VERSION : '1.0.0');
			$collector_version = $metadata['collector_version'] ?? (defined('diagnostic_collector::COLLECTOR_VERSION') ? diagnostic_collector::COLLECTOR_VERSION : '0.1');

			$collector = [
				'schema_version' => $schema_version,
				'collector_version' => $collector_version,
				'collection_id' => $collection_id,
				'generated_at' => $generated_at,
				'source' => 'fusionpbx_diagnostics_app',
				'options' => $metadata['options'] ?? [],
				'sections' => $sections,
				'errors' => $metadata['errors'] ?? [],
			];

			$files = [];
			$section_summaries = [];
			$section_json = [];
			foreach ($sections as $section_name => $section) {
				$file_path = 'sections/'.$this->sanitize_section_name($section_name).'.json';
				$json = $this->json_encode($section);
				$section_json[$file_path] = $json;
				$hash = hash('sha256', $json);
				$size = strlen($json);

				$section_summaries[] = [
					'name' => (string) $section_name,
					'status' => is_array($section) ? ($section['status'] ?? null) : null,
					'scope' => is_array($section) ? ($section['scope'] ?? null) : null,
					'record_count' => is_array($section) ? ($section['record_count'] ?? null) : null,
					'warnings' => is_array($section) ? ($section['warnings'] ?? []) : [],
					'errors' => is_array($section) ? ($section['errors'] ?? []) : [],
					'file_path' => $file_path,
					'sha256' => $hash,
					'size_bytes' => $size,
				];
				$files[] = [
					'path' => $file_path,
					'sha256' => $hash,
					'size_bytes' => $size,
				];
			}

			$collector_json = $this->json_encode($collector);
			array_unshift($files, [
				'path' => 'collector.json',
				'sha256' => hash('sha256', $collector_json),
				'size_bytes' => strlen($collector_json),
			]);

			$manifest = [
				'manifest_version' => self::MANIFEST_VERSION,
				'schema_version' => $schema_version,
				'collector_version' => $collector_version,
				'collection_id' => $collection_id,
				'generated_at' => $generated_at,
				'product' => 'FusionPBX',
				'project' => 'Siege Diagnostics',
				'sections' => $section_summaries,
				'files' => $files,
				'warnings' => $metadata['warnings'] ?? [],
				'errors' => $metadata['errors'] ?? [],
			];
			$manifest_json = $this->json_encode($manifest);

			$temp_file = tempnam(sys_get_temp_dir(), 'diagnostics_bundle_');
			if ($temp_file === false) {
				throw new RuntimeException('Unable to create temporary bundle file.');
			}

			$zip = new ZipArchive;
			if ($zip->open($temp_file, ZipArchive::OVERWRITE) !== true) {
				@unlink($temp_file);
				throw new RuntimeException('Unable to create diagnostic ZIP bundle.');
			}

			$zip->addFromString('manifest.json', $manifest_json);
			$zip->addFromString('collector.json', $collector_json);
			foreach ($section_json as $file_path => $json) {
				$zip->addFromString($file_path, $json);
			}
			$zip->close();

			$filename = 'siege-diagnostics-fusionpbx-'.$collection_id.'.zip';
			if (headers_sent()) {
				@unlink($temp_file);
				throw new RuntimeException('Unable to stream bundle after output has started.');
			}

			header('Content-Type: application/zip');
			header('Content-Disposition: attachment; filename="'.$filename.'"');
			header('Content-Length: '.filesize($temp_file));
			header('Cache-Control: no-store, no-cache, must-revalidate');
			header('Pragma: no-cache');
			readfile($temp_file);
			@unlink($temp_file);
			exit;
		}

		/**
		 * Encode JSON consistently for bundle files.
		 *
		 * @param mixed $data
		 * @return string
		 */
		private function json_encode($data) {
			$json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
			if ($json === false) {
				throw new RuntimeException('Unable to encode diagnostic bundle JSON.');
			}
			return $json;
		}

		/**
		 * Create a UUID for the collection.
		 *
		 * @return string
		 */
		private function create_uuid() {
			$data = random_bytes(16);
			$data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
			$data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
			return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
		}

		/**
		 * Sanitize a registry key for use as a section file name.
		 *
		 * @param string $section_name
		 * @return string
		 */
		private function sanitize_section_name($section_name) {
			$section_name = preg_replace('/[^a-zA-Z0-9_\-]/', '_', (string) $section_name);
			$section_name = trim($section_name, '_-');
			return $section_name !== '' ? $section_name : 'section';
		}
	}

?>
