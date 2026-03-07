// lib/src/providers/apple/apple_provider.dart

/*
 * AppleProvider
 * Sign In with Apple — uses a JWT client secret (not a static secret).
 * Apple requires the client secret to be a JWT signed with an ES256 private key.
 * Docs: https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens
 *
 * Example:
 *   DartGoth.use([
 *     AppleProvider(
 *       clientId: 'com.example.app',   // Your Services ID
 *       teamId: 'TEAMID12345',
 *       keyId: 'KEYID12345',
 *       privateKeyPem: File('AuthKey.p8').readAsStringSync(),
 *       redirectUri: 'https://yourapp.com/auth/apple/callback',
 *     ),
 *   ]);
 */

import 'dart:convert';

import 'package:crypto/crypto.dart';
import '../../core/provider.dart';

class AppleEndpoints {
  static const String authUrl = 'https://appleid.apple.com/auth/authorize';
  static const String tokenUrl = 'https://appleid.apple.com/auth/token';
  static const String keysUrl = 'https://appleid.apple.com/auth/keys';
}

class AppleProvider extends OAuthProvider {
  /// Your 10-character Apple Team ID.
  final String teamId;

  /// The Key ID from the Apple developer portal (from the .p8 file).
  final String keyId;

  /// The raw PEM-encoded ES256 private key (contents of the .p8 file).
  final String privateKeyPem;

  AppleProvider({
    required super.clientId, // Services ID (e.g. com.example.app)
    required this.teamId,
    required this.keyId,
    required this.privateKeyPem,
    required super.redirectUri,
    List<String> scopes = const ['openid', 'email', 'name'],
    super.httpClient,
  }) : super(
         clientSecret: null, // Client secret is generated as a JWT, not static
         defaultScopes: scopes,
         usePkce: false, // Apple uses nonce instead of PKCE for web flows
       );

  @override
  String get name => 'apple';

  @override
  String get displayName => 'Apple';

  /*
   * beginAuth
   * Builds the Apple authorization URL. Uses a nonce for replay protection
   * since Apple's web flow does not support PKCE code_challenge.
   * The response_mode is set to 'form_post' as Apple requires for web.
   *
   * Example:
   *   final session = await appleProvider.beginAuth(stateStore: store);
   *   return Response.found(session.authorizationUrl);
   */
  @override
  Future<OAuthSession> beginAuth({
    required StateStore stateStore,
    List<String> scopes = const [],
    AuthConfig config = const AuthConfig(),
  }) async {
    final state = generateState();
    final nonce = generateNonce();
    final allScopes = mergeScopes([...scopes, ...config.additionalScopes]);

    await stateStore.save(
      state,
      StateEntry(
        providerName: name,
        expiry: DateTime.now().add(const Duration(minutes: 10)),
        extra: {'nonce': nonce},
      ),
    );

    final url = Uri.parse(AppleEndpoints.authUrl).replace(
      queryParameters: {
        'client_id': clientId,
        'redirect_uri': redirectUri,
        'response_type': 'code',
        'scope': allScopes.join(' '),
        'state': state,
        'nonce': _hashNonce(nonce), // Apple requires SHA256(nonce)
        'response_mode': 'form_post',
        ...config.extraParams,
      },
    );

    return OAuthSession(
      authorizationUrl: url.toString(),
      state: state,
      providerName: name,
    );
  }

  /*
   * completeAuth
   * Handles Apple's form_post callback. Apple POSTs the code and user JSON
   * to your redirect URI. The [callbackParams] should contain:
   *   - 'code': the authorization code
   *   - 'state': the state string
   *   - 'user' (first sign-in only): JSON with name/email from Apple
   *
   * Example:
   *   // In your POST handler:
   *   final params = await request.bodyFields; // shelf / alfred etc.
   *   final user = await appleProvider.completeAuth(
   *     callbackParams: params, stateStore: store);
   */
  @override
  Future<OAuthUser> completeAuth({
    required Map<String, String> callbackParams,
    required StateStore stateStore,
  }) async {
    checkCallbackForErrors(callbackParams);

    final callbackState = callbackParams['state'];
    if (callbackState == null) {
      throw const InvalidStateException('Missing state in Apple callback.');
    }

    final entry = await validateAndConsumeState(callbackState, stateStore);
    final code = callbackParams['code'];
    if (code == null) {
      throw const TokenExchangeException('Missing code in Apple callback.');
    }

    // Generate the short-lived JWT client secret
    final clientSecretJwt = _generateClientSecret();

    final tokenJson = await postTokenEndpoint(AppleEndpoints.tokenUrl, {
      'client_id': clientId,
      'client_secret': clientSecretJwt,
      'code': code,
      'redirect_uri': redirectUri,
      'grant_type': 'authorization_code',
    });

    final tokens = buildTokenSet(tokenJson);

    // Apple only provides user info on the first sign-in, as a JSON string
    // in the POST body under the 'user' key.
    Map<String, dynamic> appleUserJson = {};
    if (callbackParams.containsKey('user')) {
      try {
        appleUserJson =
            jsonDecode(callbackParams['user']!) as Map<String, dynamic>;
      } catch (_) {
        // user field parse failure is non-fatal
      }
    }

    // Extract identity claims from the ID token payload (without sig verification).
    // In production: validate the id_token signature against Apple's JWKS.
    final idClaims = tokens.idToken != null
        ? _decodeJwtPayload(tokens.idToken!.jwt)
        : <String, dynamic>{};

    // Apple sends name only on first login; cache it in your own DB.
    final nameMap = appleUserJson['name'] as Map<String, dynamic>? ?? {};
    final firstName = nameMap['firstName'] as String?;
    final lastName = nameMap['lastName'] as String?;
    final email =
        (idClaims['email'] as String?) ?? appleUserJson['email'] as String?;

    // Verify nonce in ID token matches our stored nonce.
    if (tokens.idToken != null && entry.extra.containsKey('nonce')) {
      final storedNonce = entry.extra['nonce']!;
      final tokenNonce = idClaims['nonce'] as String?;
      if (tokenNonce != null &&
          !timingSafeEqual(tokenNonce, _hashNonce(storedNonce))) {
        throw const IdTokenValidationException(
          'Apple ID token nonce mismatch.',
        );
      }
    }

    final userId = idClaims['sub'] as String? ?? '';
    final emailVerified = idClaims['email_verified']?.toString() == 'true';

    return OAuthUser(
      id: userId,
      provider: name,
      email: email,
      emailVerified: emailVerified,
      name: [firstName, lastName].where((s) => s != null).join(' ').trim(),
      firstName: firstName,
      lastName: lastName,
      accessToken: tokens.accessToken.value,
      refreshToken: tokens.refreshToken?.value,
      accessTokenExpiry: tokens.accessToken.expiry,
      rawData: {
        ...idClaims,
        if (appleUserJson.isNotEmpty) 'user': appleUserJson,
      },
    );
  }

  /*
   * refreshToken
   * Exchanges an Apple refresh token for a new access token.
   * A new JWT client secret must be generated for each request.
   *
   * Example:
   *   final newTokens = await appleProvider.refreshToken(user.refreshToken!);
   */
  @override
  Future<TokenSet> refreshToken(String refreshToken) async {
    final clientSecretJwt = _generateClientSecret();
    final json = await postTokenEndpoint(AppleEndpoints.tokenUrl, {
      'client_id': clientId,
      'client_secret': clientSecretJwt,
      'refresh_token': refreshToken,
      'grant_type': 'refresh_token',
    });
    return buildTokenSet(json);
  }

  /// Generates a short-lived ES256 JWT to use as the Apple client secret.
  /// The JWT is valid for 6 months maximum, but we generate one per request
  /// to minimise exposure window.
  ///
  /// NOTE: This implementation uses a simplified HMAC-SHA256 signing as a
  /// placeholder. In production, replace with a proper ES256 (ECDSA P-256)
  /// signer using the `dart_jsonwebtoken` or `jose` package.
  String _generateClientSecret() {
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final exp = now + 300; // 5-minute expiry per request

    final header = base64Url
        .encode(utf8.encode(jsonEncode({'alg': 'ES256', 'kid': keyId})))
        .replaceAll('=', '');
    final payload = base64Url
        .encode(
          utf8.encode(
            jsonEncode({
              'iss': teamId,
              'iat': now,
              'exp': exp,
              'aud': 'https://appleid.apple.com',
              'sub': clientId,
            }),
          ),
        )
        .replaceAll('=', '');

    // ⚠️ IMPORTANT: The following signature is a placeholder using HMAC-SHA256.
    // Apple requires ES256 (ECDSA with P-256 curve). In production, use:
    //   final signer = EcdsaSigner(HashAlgorithm.sha256);
    //   final sig = signer.sign('$header.$payload', privateKeyPem);
    // Using the `dart_jsonwebtoken` package:
    //   final jwt = JWT({'iss': teamId, ...}).sign(
    //     ECPrivateKey(privateKeyPem), algorithm: JWTAlgorithm.ES256);
    final sigInput = '$header.$payload';
    final sig = base64Url
        .encode(
          Hmac(
            sha256,
            utf8.encode(privateKeyPem),
          ).convert(utf8.encode(sigInput)).bytes,
        )
        .replaceAll('=', '');

    return '$header.$payload.$sig';
  }

  /// Returns SHA-256 hex digest of a nonce string (Apple requirement).
  String _hashNonce(String nonce) {
    final bytes = utf8.encode(nonce);
    final digest = sha256.convert(bytes);
    return digest.toString(); // lowercase hex
  }

  /// Decodes the payload section of a JWT without verifying the signature.
  Map<String, dynamic> _decodeJwtPayload(String jwt) {
    try {
      final parts = jwt.split('.');
      if (parts.length < 2) return {};
      var payload = parts[1];
      while (payload.length % 4 != 0) {
        payload += '=';
      }
      final decoded = utf8.decode(
        base64Url.decode(payload.replaceAll('-', '+').replaceAll('_', '/')),
      );
      return jsonDecode(decoded) as Map<String, dynamic>;
    } catch (_) {
      return {};
    }
  }
}
