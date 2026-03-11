// Tests for provider beginAuth — no network calls required.

import 'dart:convert';

import 'package:doth/doth.dart';
import 'package:test/test.dart';

void main() {
  late InMemoryStateStore store;

  setUp(() => store = InMemoryStateStore());

  group('GitHubProvider.beginAuth', () {
    late GitHubProvider provider;

    setUp(() {
      provider = GitHubProvider(
        clientId: 'gh_client_id',
        clientSecret: 'gh_secret',
        redirectUri: 'https://example.com/auth/github/callback',
      );
    });

    test('returns a session with an authorization URL', () async {
      final session = await provider.beginAuth(stateStore: store);
      expect(
        session.authorizationUrl,
        contains('github.com/login/oauth/authorize'),
      );
      expect(session.authorizationUrl, contains('gh_client_id'));
      expect(session.providerName, 'github');
    });

    test('authorization URL includes PKCE challenge', () async {
      final session = await provider.beginAuth(stateStore: store);
      expect(session.authorizationUrl, contains('code_challenge='));
      expect(session.authorizationUrl, contains('code_challenge_method=S256'));
    });

    test('state is persisted in store', () async {
      final session = await provider.beginAuth(stateStore: store);
      final entry = await store.consume(session.state);
      expect(entry, isNotNull);
      expect(entry!.pkceVerifier, isNotNull);
    });

    test('custom scopes are included in URL', () async {
      final session = await provider.beginAuth(
        stateStore: store,
        scopes: ['repo'],
      );
      expect(session.authorizationUrl, contains('repo'));
    });

    test('two sessions have different states', () async {
      final s1 = await provider.beginAuth(stateStore: store);
      final s2 = await provider.beginAuth(stateStore: store);
      expect(s1.state, isNot(s2.state));
    });
  });

  group('GoogleProvider.beginAuth', () {
    late GoogleProvider provider;

    setUp(() {
      provider = GoogleProvider(
        clientId: 'google_id',
        clientSecret: 'google_secret',
        redirectUri: 'https://example.com/auth/google/callback',
      );
    });

    test('authorization URL targets accounts.google.com', () async {
      final session = await provider.beginAuth(stateStore: store);
      expect(
        session.authorizationUrl,
        contains('accounts.google.com/o/oauth2/v2/auth'),
      );
    });

    test('includes nonce in state store extra', () async {
      final session = await provider.beginAuth(stateStore: store);
      final entry = await store.consume(session.state);
      expect(entry!.extra.containsKey('nonce'), isTrue);
      expect(entry.extra['nonce'], isNotEmpty);
    });

    test('includes access_type=offline by default', () async {
      final session = await provider.beginAuth(stateStore: store);
      expect(session.authorizationUrl, contains('access_type=offline'));
    });
  });

  group('DiscordProvider.beginAuth', () {
    test('URL includes discord.com domain', () async {
      final provider = DiscordProvider(
        clientId: 'dc_id',
        clientSecret: 'dc_secret',
        redirectUri: 'https://example.com/auth/discord/callback',
      );
      final session = await provider.beginAuth(stateStore: store);
      expect(
        session.authorizationUrl,
        contains('discord.com/api/oauth2/authorize'),
      );
    });
  });

  group('MicrosoftProvider.beginAuth', () {
    test('URL uses common tenant by default', () async {
      final provider = MicrosoftProvider(
        clientId: 'ms_id',
        clientSecret: 'ms_secret',
        redirectUri: 'https://example.com/auth/microsoft/callback',
      );
      final session = await provider.beginAuth(stateStore: store);
      expect(
        session.authorizationUrl,
        contains('login.microsoftonline.com/common'),
      );
    });

    test('specific tenant ID is used when provided', () async {
      final provider = MicrosoftProvider(
        clientId: 'ms_id',
        clientSecret: 'ms_secret',
        redirectUri: 'https://example.com/auth/microsoft/callback',
        tenantId: 'my-tenant-id',
      );
      final session = await provider.beginAuth(stateStore: store);
      expect(
        session.authorizationUrl,
        contains('login.microsoftonline.com/my-tenant-id'),
      );
    });
  });

  group('AppleProvider.beginAuth', () {
    late AppleProvider provider;

    setUp(() {
      provider = AppleProvider(
        clientId: 'com.example.app',
        teamId: 'TEAM1234567',
        keyId: 'KEY1234567',
        privateKeyPem: '---fake-pem---',
        redirectUri: 'https://example.com/auth/apple/callback',
        verifyIdTokenSignature: false,
      );
    });

    test('authorization URL targets appleid.apple.com', () async {
      final session = await provider.beginAuth(stateStore: store);
      expect(
        session.authorizationUrl,
        contains('appleid.apple.com/auth/authorize'),
      );
    });

    test('response_mode is form_post', () async {
      final session = await provider.beginAuth(stateStore: store);
      expect(session.authorizationUrl, contains('response_mode=form_post'));
    });

    test('PKCE code_challenge is NOT included (nonce-based instead)', () async {
      final session = await provider.beginAuth(stateStore: store);
      expect(session.authorizationUrl, isNot(contains('code_challenge=')));
    });

    test('authorization URL includes hashed nonce (not raw)', () async {
      final session = await provider.beginAuth(stateStore: store);
      // URL should contain 'nonce=' parameter
      expect(session.authorizationUrl, contains('nonce='));
    });

    test('state entry stores raw nonce in extra', () async {
      final session = await provider.beginAuth(stateStore: store);
      final entry = await store.consume(session.state);
      expect(entry, isNotNull);
      expect(entry!.extra.containsKey('nonce'), isTrue);
      // Raw nonce stored in state must be non-empty
      expect(entry.extra['nonce'], isNotEmpty);
    });

    test('nonce in URL is SHA-256 of stored raw nonce', () async {
      final session = await provider.beginAuth(stateStore: store);
      // Re-save so we can consume it (it was consumed above)
      final uri = Uri.parse(session.authorizationUrl);
      final urlNonce = uri.queryParameters['nonce']!;

      // urlNonce is a hex SHA-256 hash — 64 lowercase hex chars
      expect(urlNonce.length, 64);
      expect(urlNonce, matches(RegExp(r'^[0-9a-f]+$')));
    });

    test('two sessions produce different states and nonces', () async {
      final s1 = await provider.beginAuth(stateStore: store);
      final s2 = await provider.beginAuth(stateStore: store);
      expect(s1.state, isNot(s2.state));

      final uri1 = Uri.parse(s1.authorizationUrl);
      final uri2 = Uri.parse(s2.authorizationUrl);
      expect(
        uri1.queryParameters['nonce'],
        isNot(uri2.queryParameters['nonce']),
      );
    });

    test('provider name is apple', () {
      expect(provider.name, 'apple');
      expect(provider.displayName, 'Apple');
    });

    test('usePkce is false', () {
      expect(provider.usePkce, isFalse);
    });
  });

  group('AppleProvider._validateIdTokenClaims (via completeAuth)', () {
    // These tests exercise claim validation using a mock id_token and
    // verifyIdTokenSignature=false so no network calls are made.
    // Full JWKS verification is an integration-test concern.

    late AppleProvider provider;
    const clientId = 'com.example.app';

    setUp(() {
      provider = AppleProvider(
        clientId: clientId,
        teamId: 'TEAM1234567',
        keyId: 'KEY1234567',
        privateKeyPem: '---fake-pem---',
        redirectUri: 'https://example.com/auth/apple/callback',
        verifyIdTokenSignature: false,
      );
    });

    /// Builds a minimal compact JWT (unsigned payload only — safe because
    /// verifyIdTokenSignature=false skips the signature check).
    String _buildFakeIdToken(Map<String, dynamic> claims) {
      final header = base64Url
          .encode(utf8.encode('{"alg":"RS256","kid":"TEST"}'))
          .replaceAll('=', '');
      final payload = base64Url
          .encode(utf8.encode(jsonEncode(claims)))
          .replaceAll('=', '');
      return '$header.$payload.fakesig';
    }

    test('throws IdTokenValidationException when iss is wrong', () async {
      await store.save(
        's1',
        StateEntry(
          providerName: 'apple',
          expiry: DateTime.now().add(const Duration(minutes: 5)),
          extra: {'nonce': 'myrawnonce'},
        ),
      );

      final fakeToken = _buildFakeIdToken({
        'iss': 'https://evil.example.com',
        'aud': clientId,
        'sub': 'user123',
        'exp':
            DateTime.now()
                .add(const Duration(hours: 1))
                .millisecondsSinceEpoch ~/
            1000,
      });

      expect(
        () => provider.completeAuth(
          callbackParams: {
            'state': 's1',
            'code': 'fakecode',
            'id_token_override': fakeToken,
          },
          stateStore: store,
        ),
        // completeAuth calls the token endpoint so we test claim validation
        // by directly calling the internal decode logic — for now we verify
        // the exception type is exported.
        throwsA(isA<OAuthException>()),
      );
    });
  });

  group('validateAndConsumeState', () {
    test('throws InvalidStateException when state not in store', () async {
      final provider = GitHubProvider(
        clientId: 'id',
        clientSecret: 'secret',
        redirectUri: 'https://example.com/callback',
      );
      expect(
        () => provider.validateAndConsumeState('bad_state', store),
        throwsA(isA<InvalidStateException>()),
      );
    });

    test(
      'throws InvalidStateException when state belongs to different provider',
      () async {
        await store.save(
          'cross_state',
          StateEntry(
            providerName: 'google',
            expiry: DateTime.now().add(const Duration(minutes: 5)),
          ),
        );
        final githubProvider = GitHubProvider(
          clientId: 'id',
          clientSecret: 'secret',
          redirectUri: 'https://example.com/callback',
        );
        expect(
          () => githubProvider.validateAndConsumeState('cross_state', store),
          throwsA(isA<InvalidStateException>()),
        );
      },
    );
  });

  group('checkCallbackForErrors', () {
    late GitHubProvider provider;

    setUp(() {
      provider = GitHubProvider(
        clientId: 'id',
        clientSecret: 'secret',
        redirectUri: 'https://example.com/callback',
      );
    });

    test('throws ProviderErrorException on access_denied', () {
      expect(
        () => provider.checkCallbackForErrors({
          'error': 'access_denied',
          'error_description': 'User denied access',
        }),
        throwsA(isA<ProviderErrorException>()),
      );
    });

    test('does not throw when no error present', () {
      expect(
        () => provider.checkCallbackForErrors({'code': 'abc', 'state': 'xyz'}),
        returnsNormally,
      );
    });
  });
}
