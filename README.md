# doth

**A multi-provider OAuth2 authentication library for Dart backends.**  
Inspired by [markbates/goth](https://github.com/markbates/goth) for Go.

---

## Features

- **Provider-agnostic** — one clean API, pluggable providers  
- **PKCE S256 by default** (RFC 7636) — protects every authorization code flow  
- **Cryptographic state** — CSRF protection via timing-safe comparison  
- **Token refresh** — built-in `refreshToken()` on every provider  
- **Framework-agnostic core** — works with `shelf`, `dart_frog`, `alfred`, or raw `dart:io`  
- **Pluggable state store** — swap the default in-memory store for Redis, Postgres, etc.  
- **Apple Sign-In** — JWT client secret generation + nonce verification  

---

## Built-in Providers

| Provider   | PKCE | Refresh Token | Notes |
|------------|------|---------------|-------|
| GitHub     | ✅   | ⚠️ Apps only  | Fetches verified primary email separately |
| Google     | ✅   | ✅            | OIDC; nonce verified in ID token |
| Apple      | —    | ✅            | JWT client secret; form_post callback |
| Meta       | ✅   | Token exchange| Graph API v19 |
| Discord    | ✅   | ✅            | CDN avatar URL auto-constructed |
| Microsoft  | ✅   | ✅            | Supports single/multi-tenant, Entra ID |

---

## Installation

```yaml
# pubspec.yaml
dependencies:
  doth: ^0.1.0
```

---

## Quick Start (shelf)

```dart
import 'package:doth/doth.dart';
import 'package:doth/shelf_adapter.dart';
import 'package:shelf_router/shelf_router.dart';

void main() async {
  // 1. Register providers
  Doth.use([
    GitHubProvider(
      clientId: Platform.environment['GITHUB_CLIENT_ID']!,
      clientSecret: Platform.environment['GITHUB_CLIENT_SECRET']!,
      redirectUri: 'https://yourapp.com/auth/github/callback',
    ),
    GoogleProvider(
      clientId: Platform.environment['GOOGLE_CLIENT_ID']!,
      clientSecret: Platform.environment['GOOGLE_CLIENT_SECRET']!,
      redirectUri: 'https://yourapp.com/auth/google/callback',
    ),
  ]);

  // 2. Wire up routes
  final router = Router()
    ..get('/auth/<provider>', ShelfAdapter.beginAuthHandler)
    ..get('/auth/<provider>/callback', ShelfAdapter.callbackHandler(
      onSuccess: (user, request) async {
        // user.id, user.email, user.name, user.accessToken ...
        return Response.ok('Welcome ${user.name}!');
      },
      onError: (e, request) async => Response.forbidden(e.message),
    ));
}
```

---

## Apple Sign-In (form_post)

Apple uses `response_mode=form_post`, so the callback is a POST:

```dart
Doth.use([
  AppleProvider(
    clientId: 'com.example.myapp',       // Your Services ID
    teamId: Platform.environment['APPLE_TEAM_ID']!,
    keyId: Platform.environment['APPLE_KEY_ID']!,
    privateKeyPem: File('AuthKey.p8').readAsStringSync(),
    redirectUri: 'https://yourapp.com/auth/apple/callback',
  ),
]);

router.post('/auth/apple/callback',
  ShelfAdapter.postCallbackHandler(
    onSuccess: ...,
    onError: ...,
  ));
```

---

## Writing a Custom Provider

```dart
class MyProvider extends OAuthProvider {
  MyProvider({
    required super.clientId,
    required super.clientSecret,
    required super.redirectUri,
  }) : super(defaultScopes: ['user']);

  @override String get name => 'myprovider';

  @override
  Future<OAuthSession> beginAuth({
    required StateStore stateStore,
    List<String> scopes = const [],
    AuthConfig config = const AuthConfig(),
  }) async {
    final state = generateState();
    final pkce = PkceChallenge.generate();
    await stateStore.save(state, StateEntry(
      providerName: name,
      expiry: DateTime.now().add(const Duration(minutes: 10)),
      pkceVerifier: pkce.verifier,
    ));
    final url = Uri.https('provider.example.com', '/oauth/authorize', {
      'client_id': clientId,
      'redirect_uri': redirectUri,
      'state': state,
      'code_challenge': pkce.challenge,
      'code_challenge_method': 'S256',
    });
    return OAuthSession(
      authorizationUrl: url.toString(),
      state: state,
      providerName: name,
    );
  }

  @override
  Future<OAuthUser> completeAuth({
    required Map<String, String> callbackParams,
    required StateStore stateStore,
  }) async {
    checkCallbackForErrors(callbackParams);
    final entry = await validateAndConsumeState(callbackParams['state']!, stateStore);
    final tokenJson = await postTokenEndpoint('https://provider.example.com/token', {
      'client_id': clientId,
      'client_secret': clientSecret!,
      'code': callbackParams['code']!,
      'redirect_uri': redirectUri,
      'grant_type': 'authorization_code',
      if (entry.pkceVerifier != null) 'code_verifier': entry.pkceVerifier!,
    });
    final tokens = buildTokenSet(tokenJson);
    final profile = await getWithBearerToken('https://provider.example.com/me',
        tokens.accessToken.value);
    return OAuthUser(
      id: profile['id'].toString(),
      provider: name,
      accessToken: tokens.accessToken.value,
      rawData: profile,
    );
  }

  @override
  Future<TokenSet> refreshToken(String refreshToken) async {
    final json = await postTokenEndpoint('https://provider.example.com/token', {
      'grant_type': 'refresh_token',
      'refresh_token': refreshToken,
      'client_id': clientId,
      'client_secret': clientSecret!,
    });
    return buildTokenSet(json);
  }
}
```

---

## Custom State Store (Redis example)

```dart
class RedisStateStore implements StateStore {
  final RedisClient redis;
  RedisStateStore(this.redis);

  @override
  Future<void> save(String state, StateEntry entry) =>
      redis.setEx(state, 600, jsonEncode({
        'provider': entry.providerName,
        'verifier': entry.pkceVerifier,
        'extra': entry.extra,
      }));

  @override
  Future<StateEntry?> consume(String state) async {
    final raw = await redis.getDel(state);
    if (raw == null) return null;
    final data = jsonDecode(raw) as Map;
    return StateEntry(
      providerName: data['provider'],
      expiry: DateTime.now().add(const Duration(minutes: 10)),
      pkceVerifier: data['verifier'],
      extra: Map<String, String>.from(data['extra'] ?? {}),
    );
  }

  @override
  Future<void> purgeExpired() async {} // Redis TTL handles expiry
}

// Use it:
Doth.stateStore = RedisStateStore(myRedisClient);
```

---

## Security Checklist

- [x] PKCE S256 on every flow (except Apple form_post which uses nonce)
- [x] Cryptographically random state (256-bit entropy)
- [x] Timing-safe state comparison (prevents timing oracle attacks)
- [x] State is consumed on use (prevents replay)
- [x] State entries expire (default 10 minutes)
- [x] Client secrets never logged or exposed in URLs
- [x] Apple nonce hashed with SHA-256 before sending
- [x] Cross-provider state confusion detection
- [ ] Production: use a distributed state store (Redis/DB) in multi-instance deployments
- [ ] Production: validate JWT signatures (Google/Apple ID tokens) with JWKS
- [x] Production: replace Apple ES256 placeholder with a real ECDSA signer

---

## License

MIT
