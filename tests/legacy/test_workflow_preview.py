"""Preview policy tests: no real sockets, browsers or model calls."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.parse import quote

import workflow_artifacts as artifacts
import workflow_preview as preview
from workflow_core import ContractError


class PreviewTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        for module in (preview, artifacts):
            changed = patch.object(module, 'DIRECTORY', self.directory)
            changed.start()
            self.addCleanup(changed.stop)
        self.packet = artifacts.validate_artifact_packet({
            'kind': 'artifact-create', 'id': 'preview-test', 'objective': 'Show a static preview.',
            'allowed_paths': ['index.html', 'style.css', '자료/요약.md'],
            'generation_profile': 'huihui-qwen38-q6kl-v1', 'authorityId': 'preview-test-contract',
            'validation_packs': ['text'],
        })
        self.candidate = artifacts.create_artifact_candidate(self.packet, self.directory / 'run/candidate')
        self.contents = {'index.html': '<!doctype html><html><body>확인</body></html>\n',
                         'style.css': 'body { color: navy; }\n', '자료/요약.md': '# 요약\n'}
        artifacts.apply_new_files(self.packet, self.candidate,
            {'files': [{'path': path, 'content': content} for path, content in self.contents.items()]})
        self.packet_sha = json.loads((self.candidate.parent / '.candidate.artifact-owner.json').read_text())['packet_sha256']
        self.nonce, self.host = 'a' * 32, '127.0.0.1:41234'
        self.url = '/' + self.nonce + '/index.html'

    def assets(self):
        return preview.safe_assets(self.candidate, self.packet['allowed_paths'])

    def request(self, method='GET', target=None, headers=None, assets=None):
        return preview._response(method, target or self.url,
            headers if headers is not None else [('Host', self.host)], assets or self.assets(), self.nonce, self.host)

    def test_exact_frozen_bytes_and_unicode_paths(self):
        assets = self.assets()
        self.assertEqual(assets, {path: text.encode('utf-8') for path, text in self.contents.items()})
        status, headers, body = self.request(target='/' + self.nonce + '/' + quote('자료/요약.md', safe='/'))
        self.assertEqual(status, 200)
        self.assertEqual(body, '# 요약\n'.encode())
        self.assertEqual(headers['Content-Type'], 'text/plain; charset=utf-8')

    def test_source_mutation_after_freeze_does_not_change_http_output(self):
        assets = self.assets()
        (self.candidate / 'index.html').write_text('modified after freeze\n')
        self.assertEqual(self.request(assets=assets)[2], self.contents['index.html'].encode())
        with self.assertRaises(ContractError):
            self.assets()

    def test_unapproved_subset_extra_files_symlinks_and_non_artifacts_rejected(self):
        with self.assertRaises(ContractError):
            preview.safe_assets(self.candidate, ['index.html'])
        (self.candidate / 'extra.txt').write_text('unexpected\n')
        with self.assertRaises(ContractError):
            self.assets()
        (self.candidate / 'extra.txt').unlink()
        (self.candidate / 'index.html').unlink()
        (self.candidate / 'index.html').symlink_to(self.directory / 'unrelated')
        with self.assertRaises(ContractError):
            self.assets()
        empty = self.directory / 'not-an-artifact'
        empty.mkdir()
        with self.assertRaises((ContractError, FileNotFoundError)):
            preview.safe_assets(empty, ['index.html'])

    def test_sensitive_unsupported_and_ambiguous_url_paths_rejected(self):
        for path in ('.env', '.git/config', '../index.html', 'image.svg', 'a%20.html', 'a?.html', 'a#.html'):
            with self.subTest(path=path), self.assertRaises(ContractError):
                preview.safe_assets(self.candidate, [path])

    def test_oversized_file_is_rejected_before_freezing(self):
        (self.candidate / 'index.html').write_bytes(b'x' * (preview.MAX_FILE_BYTES + 1))
        with self.assertRaises(ContractError):
            self.assets()

    def test_total_byte_cap_rejects_even_individually_bounded_matching_files(self):
        paths = ['part-' + str(index) + '.txt' for index in range(5)]
        packet = artifacts.validate_artifact_packet({**self.packet, 'allowed_paths': paths})
        candidate = artifacts.create_artifact_candidate(packet, self.directory / 'large/candidate')
        # Model-output validation normally rejects this already. Independently
        # exercise the preview boundary using a forged oversized output receipt.
        data = b'x' * 60000
        manifest = {}
        for path in paths:
            (candidate / path).write_bytes(data)
            manifest[path] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
        (candidate.parent / '.candidate.artifact-output.json').write_text(json.dumps(manifest))
        with self.assertRaises(ContractError):
            preview.safe_assets(candidate, paths)

    def test_candidate_and_receipt_symlinks_are_not_followed(self):
        alias = self.directory / 'alias'
        alias.symlink_to(self.candidate, target_is_directory=True)
        with self.assertRaises(ContractError):
            preview.safe_assets(alias, self.packet['allowed_paths'])
        receipt = self.candidate.parent / '.candidate.artifact-output.json'
        copy = receipt.with_name('held-receipt.json')
        receipt.rename(copy)
        receipt.symlink_to(copy)
        with self.assertRaises(OSError):
            self.assets()

    def test_get_and_head_preserve_html_without_rewriting(self):
        status, headers, body = self.request()
        self.assertEqual(status, 200)
        self.assertEqual(body, self.contents['index.html'].encode())
        head_status, head_headers, head_body = self.request(method='HEAD')
        self.assertEqual(head_status, 200)
        self.assertEqual(head_headers['Content-Length'], headers['Content-Length'])
        self.assertEqual(head_body, b'')

    def test_all_security_headers_on_success_and_error(self):
        for target in (self.url, '/missing'):
            headers = self.request(target=target)[1]
            self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
            self.assertEqual(headers['Cache-Control'], 'no-store, max-age=0')
            self.assertIn('display-capture=()', headers['Permissions-Policy'])
            policy = headers['Content-Security-Policy']
            for directive in ("default-src 'none'", "connect-src 'none'", "frame-ancestors 'none'",
                              "worker-src 'none'", "form-action 'none'", 'sandbox allow-scripts'):
                self.assertIn(directive, policy)
            for permission in ('allow-same-origin', 'allow-top-navigation', 'allow-popups', 'allow-downloads'):
                self.assertNotIn(permission, policy)
            self.assertNotIn('Access-Control-Allow-Origin', headers)

    def test_strict_host_rejects_alias_foreign_port_and_duplicates(self):
        for hosts in ([], [('Host', 'localhost:41234')], [('Host', '127.0.0.1:41235')],
                      [('Host', 'evil.test')], [('Host', self.host), ('Host', self.host)]):
            with self.subTest(hosts=hosts):
                self.assertEqual(self.request(headers=hosts)[0], 400)

    def test_cross_site_origin_and_fetch_metadata_are_denied(self):
        bad = [[('Origin', 'https://evil.test')], [('Origin', 'null')],
               [('Sec-Fetch-Site', 'cross-site')], [('Sec-Fetch-Site', 'same-site')],
               [('Origin', 'http://' + self.host), ('Origin', 'http://' + self.host)]]
        for additional in bad:
            with self.subTest(additional=additional):
                self.assertEqual(self.request(headers=[('Host', self.host), *additional])[0], 403)
        self.assertEqual(self.request(headers=[('Host', self.host), ('Sec-Fetch-Site', 'none')])[0], 200)
        self.assertEqual(self.request(headers=[('Host', self.host), ('Origin', 'http://' + self.host),
                                                ('Sec-Fetch-Site', 'same-origin')])[0], 200)

    def test_directory_query_traversal_encoded_slashes_and_double_encoding_rejected(self):
        targets = ['/', '/' + self.nonce + '/', self.url + '?x=1', self.url + '?', self.url + '#part',
                   '/' + self.nonce + '/../index.html', '/' + self.nonce + '/%2e%2e/index.html',
                   '/' + self.nonce + '/%252e%252e/index.html', '/' + self.nonce + '/sub%2findex.html',
                   '/' + self.nonce + '/%69ndex.html', '/' + self.nonce + '/index.html/extra',
                   '/wrongnonce/index.html', 'http://evil.test' + self.url]
        for target in targets:
            with self.subTest(target=target):
                self.assertEqual(self.request(target=target)[0], 404)

    def test_post_and_other_mutating_methods_never_run(self):
        for method in ('POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE', 'CONNECT'):
            with self.subTest(method=method):
                status, headers, body = self.request(method=method)
                self.assertEqual(status, 405)
                self.assertEqual(headers['Allow'], 'GET, HEAD')
                self.assertEqual(body, b'')

    def _serve_mocked(self, evidence, action):
        server = Mock(server_address=('127.0.0.1', 41234))
        server.handle_request.side_effect = action
        output = io.StringIO()
        with patch.object(preview, '_PreviewServer', return_value=server) as factory, \
             patch.object(preview.signal, 'getitimer', return_value=(0.0, 0.0)), \
             patch.object(preview.signal, 'setitimer') as timer, \
             patch.object(preview.signal, 'signal') as signals, contextlib.redirect_stdout(output):
            result = preview.serve_preview(self.candidate, self.packet['allowed_paths'], evidence, self.packet_sha, 5)
        return result, server, factory, timer, signals, output.getvalue()

    def test_foreground_ttl_records_session_and_always_closes_without_real_socket(self):
        evidence = self.directory / 'preview-evidence'
        result, server, factory, timer, signals, output = self._serve_mocked(evidence, preview._PreviewStopped('ttl-expired'))
        factory.assert_called_once()
        self.assertEqual(factory.call_args.args[0], ('127.0.0.1', 0))
        server.server_close.assert_called_once()
        self.assertEqual(result['reason'], 'ttl-expired')
        metadata = json.loads((evidence / 'preview.json').read_text())
        stopped = json.loads((evidence / 'stopped.json').read_text())
        self.assertEqual(metadata, json.loads(output))
        self.assertEqual(metadata['packet_sha256'], self.packet_sha)
        self.assertEqual(metadata['session_id'], stopped['session_id'])
        self.assertEqual(metadata['pid'], os.getpid())
        self.assertEqual(metadata['host'], '127.0.0.1')
        self.assertEqual(metadata['port'], 41234)
        self.assertEqual(metadata['urls']['index.html'], metadata['url'])
        self.assertEqual(set(metadata['files']), set(self.packet['allowed_paths']))
        self.assertTrue(stopped['server_closed'])
        self.assertTrue(metadata['url'].startswith('http://127.0.0.1:41234/'))
        self.assertTrue(metadata['url'].endswith('/index.html'))
        self.assertEqual(timer.call_args_list[0].args, (signal.ITIMER_REAL, 5))
        self.assertEqual(timer.call_args_list[-1].args, (signal.ITIMER_REAL, 0))
        self.assertEqual(signals.call_count, 6)

    def test_ctrl_c_and_exception_cleanup_record_stop_without_http_shutdown(self):
        evidence = self.directory / 'interrupted'
        result, server, *_ = self._serve_mocked(evidence, KeyboardInterrupt())
        self.assertEqual(result['reason'], 'interrupt')
        server.server_close.assert_called_once()
        self.assertEqual(self.request(target='/' + self.nonce + '/shutdown')[0], 404)
        failure = self.directory / 'failed'
        server = Mock(server_address=('127.0.0.1', 41234))
        server.handle_request.side_effect = RuntimeError('fixture failure')
        with patch.object(preview, '_PreviewServer', return_value=server), \
             patch.object(preview.signal, 'getitimer', return_value=(0.0, 0.0)), \
             patch.object(preview.signal, 'setitimer'), patch.object(preview.signal, 'signal'), \
             contextlib.redirect_stdout(io.StringIO()), self.assertRaises(RuntimeError):
            preview.serve_preview(self.candidate, self.packet['allowed_paths'], failure, self.packet_sha, 5)
        server.server_close.assert_called_once()
        self.assertEqual(json.loads((failure / 'stopped.json').read_text())['reason'], 'error')

    def test_packet_drift_invalid_ttl_and_evidence_overlap_fail_before_binding(self):
        with patch.object(preview, '_PreviewServer') as factory:
            for ttl in (0, 301, True):
                with self.subTest(ttl=ttl), self.assertRaises(ContractError):
                    preview.serve_preview(self.candidate, self.packet['allowed_paths'], self.directory / 'evidence', self.packet_sha, ttl)
            with self.assertRaises(ContractError):
                preview.serve_preview(self.candidate, self.packet['allowed_paths'], self.directory / 'evidence', 'b' * 64, 5)
            with self.assertRaises(ContractError):
                preview.serve_preview(self.candidate, self.packet['allowed_paths'], self.candidate / 'evidence', self.packet_sha, 5)
            factory.assert_not_called()

    def test_evidence_is_new_and_does_not_follow_symlink_ancestors(self):
        exists = self.directory / 'existing-evidence'
        exists.mkdir()
        with patch.object(preview, '_PreviewServer') as factory, self.assertRaises(FileExistsError):
            preview.serve_preview(self.candidate, self.packet['allowed_paths'], exists, self.packet_sha, 5)
        factory.assert_not_called()
        outside = self.directory.parent / ('preview-outside-' + self.directory.name)
        # The target need not exist: a symlink is rejected before creating it.
        (self.directory / 'alias').symlink_to(outside, target_is_directory=True)
        with patch.object(preview, '_PreviewServer') as factory, self.assertRaises(ContractError):
            preview.serve_preview(self.candidate, self.packet['allowed_paths'], self.directory / 'alias/evidence', self.packet_sha, 5)
        factory.assert_not_called()


if __name__ == '__main__':
    unittest.main()
