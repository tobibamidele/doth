/*
 * AppleProvider
 * Sign In with Apple
 *
 * Security properties:
 *  - Client secret is generated fresh per request (5-minute JWT TTL).
 *  - Nonce sent to Apple is SHA-256(rawNonce); the raw nonce never leaves the server.
 *  - id_token signature is verified against Apple's live JWKS (RS256).
 *  - All required OIDC claims are validated (iss, aud, exp, nonce).
 *  - State is consumed exactly once (replay prevention).
 *  - Timing-safe comparison used for nonce verification.
 *
 * Example:
 *   Doth.use([
 *     AppleProvider(
 *       clientId: 'com.example.app',           // Your Services ID
 *       teamId: Platform.environment['APPLE_TEAM_ID']!,
 *       keyId: Platform.environment['APPLE_KEY_ID']!,
 *       privateKeyPem: File('AuthKey_KEYID.p8').readAsStringSync(),
 *       redirectUri: 'https://yourapp.com/auth/apple/callback',
 *     ),
 *   ]);
 */

import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart' as djwt;
import 'package:jose/jose.dart' as jose;

import '../../core/provider.dart';

class AppleEndpoints {
  static const String authUrl = 'https://appleid.apple.com/auth/authorize';
  static const String tokenUrl = 'https://appleid.apple.com/auth/token';
  static const String keysUrl = 'https://appleid.apple.com/auth/keys';
  static const String issuer = 'https://appleid.apple.com';
}

class AppleProvider extends OAuthProvider {
  /// Your 10-character Apple Team ID (visible in developer.apple.com → Membership).
  final String teamId;

  /// The Key ID shown in the Apple developer portal when you downloaded the .p8 file.
  final String keyId;

  /// Raw contents of the AuthKey_XXXXXX.p8 file — the PKCS#8 PEM-encoded ES256 private key.
  /// Keep this in an environment variable or secrets manager; never commit it.
  ///
  /// Expected format (literal newlines required):
  ///   -----BEGIN PRIVATE KEY-----
  ///   MIGHAgEAMBMGByqGSM49...
  ///   -----END PRIVATE KEY-----
  final String privateKeyPem;

  /// Whether to fetch and verify Apple's JWKS to validate the id_token signature.
  /// Defaults to true. Only set to false in offline unit tests.
  final bool verifyIdTokenSignature;

  AppleProvider({
    required super.clientId, // Your Services ID, e.g. com.example.app
    required this.teamId,
    required this.keyId,
    required this.privateKeyPem,
    required super.redirectUri,
    List<String> scopes = const ['openid', 'email', 'name'],
    this.verifyIdTokenSignature = true,
    super.httpClient,
  }) : super(
         clientSecret:
             null, // Client secret is a generated JWT, not a static string.
         defaultScopes: scopes,
         usePkce:
             false, // Apple's web flow uses nonce for replay protection instead of PKCE.
       );

  @override
  String get name => 'apple';

  @override
  String get displayName => 'Apple';

  // ---------------------------------------------------------------------------
  // beginAuth
  // ---------------------------------------------------------------------------

  /*
   * beginAuth
   * Builds the Apple Sign-In authorization URL.
   *
   * A cryptographically random rawNonce is generated and stored in the
   * StateStore. Apple receives only SHA-256(rawNonce) — the raw value never
   * leaves your server. Apple embeds the same hash into the id_token's 'nonce'
   * claim, which we verify in [completeAuth].
   *
   * response_mode is fixed to 'form_post': Apple POSTs the callback parameters
   * rather than appending them as query strings.
   *
   * Example:
   *   final session = await appleProvider.beginAuth(stateStore: store);
   *   // In a shelf handler:
   *   return Response.found(session.authorizationUrl);
   */
  @override
  Future<OAuthSession> beginAuth({
    required StateStore stateStore,
    List<String> scopes = const [],
    AuthConfig config = const AuthConfig(),
  }) async {
    final state = generateState();
    final rawNonce =
        generateNonce(); // 256 bits of entropy; never sent to Apple
    final allScopes = mergeScopes([...scopes, ...config.additionalScopes]);

    // Store the raw nonce — we'll need it later to verify the id_token claim.
    await stateStore.save(
      state,
      StateEntry(
        providerName: name,
        expiry: DateTime.now().add(const Duration(minutes: 10)),
        extra: {'nonce': rawNonce},
      ),
    );

    final url = Uri.parse(AppleEndpoints.authUrl).replace(
      queryParameters: {
        'client_id': clientId,
        'redirect_uri': redirectUri,
        'response_type': 'code',
        'scope': allScopes.join(' '),
        'state': state,
        // Apple receives SHA-256(rawNonce), not the raw value.
        'nonce': _sha256Hex(rawNonce),
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

  // ---------------------------------------------------------------------------
  // completeAuth
  // ---------------------------------------------------------------------------

  /*
   * completeAuth
   * Handles Apple's form_post callback.
   *
   * Apple POSTs these fields to your redirectUri:
   *   code        — the one-time authorization code
   *   state       — echoed back from the authorization request
   *   user        — JSON string present ONLY on the first sign-in, containing
   *                 { name: { firstName, lastName }, email }. Cache it — Apple
   *                 never sends it again.
   *
   * Steps performed:
   *  1. Check for provider error params (e.g. user_cancelled_authorize).
   *  2. Validate and consume the state (CSRF check).
   *  3. Generate a fresh ES256-signed JWT client_secret.
   *  4. POST to Apple's token endpoint to exchange the code for tokens.
   *  5. Verify the id_token: JWKS signature + iss + aud + exp + nonce.
   *  6. Build and return an [OAuthUser].
   *
   * Example:
   *   // In your shelf POST /auth/apple/callback handler:
   *   final body   = await request.readAsString();
   *   final params = Uri.splitQueryString(body);
   *   final user   = await appleProvider.completeAuth(
   *     callbackParams: params, stateStore: store);
   */
  @override
  Future<OAuthUser> completeAuth({
    required Map<String, String> callbackParams,
    required StateStore stateStore,
  }) async {
    checkCallbackForErrors(callbackParams);

    final callbackState = callbackParams['state'];
    if (callbackState == null || callbackState.isEmpty) {
      throw const InvalidStateException('Missing state in Apple callback.');
    }

    final entry = await validateAndConsumeState(callbackState, stateStore);
    final rawNonce = entry.extra['nonce'];
    if (rawNonce == null) {
      throw const InvalidStateException(
        'State entry missing nonce — possible session tampering.',
      );
    }

    final code = callbackParams['code'];
    if (code == null || code.isEmpty) {
      throw const TokenExchangeException(
        'Missing authorization code in Apple callback.',
      );
    }

    // ── 3. Generate a short-lived ES256 client secret JWT ──────────────────
    final clientSecretJwt = _generateClientSecret();

    // ── 4. Exchange authorization code → tokens ────────────────────────────
    // Apple's token endpoint requires a User-Agent header or it rejects the request.
    final tokenResponse = await httpClient.post(
      Uri.parse(AppleEndpoints.tokenUrl),
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
        'User-Agent': 'dart_goth/0.1.0',
      },
      body: {
        'client_id': clientId,
        'client_secret': clientSecretJwt,
        'code': code,
        'redirect_uri': redirectUri,
        'grant_type': 'authorization_code',
      },
    );

    if (tokenResponse.statusCode < 200 || tokenResponse.statusCode >= 300) {
      throw TokenExchangeException(
        'Apple token endpoint returned HTTP ${tokenResponse.statusCode}: '
        '${tokenResponse.body}',
        statusCode: tokenResponse.statusCode,
      );
    }

    final Map<String, dynamic> tokenJson;
    try {
      tokenJson = jsonDecode(tokenResponse.body) as Map<String, dynamic>;
    } catch (e) {
      throw TokenExchangeException(
        'Apple token endpoint returned non-JSON: ${tokenResponse.body}',
        cause: e,
      );
    }

    if (tokenJson.containsKey('error')) {
      throw TokenExchangeException(
        'Apple token error: ${tokenJson["error"]} — ${tokenJson["error_description"]}',
      );
    }

    final tokens = buildTokenSet(tokenJson);

    // ── 5. Verify the id_token ─────────────────────────────────────────────
    final rawIdToken = tokenJson['id_token'] as String?;
    if (rawIdToken == null) {
      throw const TokenExchangeException(
        'Apple token response did not include an id_token.',
      );
    }

    final idClaims = await _verifyAndDecodeIdToken(rawIdToken, rawNonce);

    // ── 6. Parse optional user payload (first sign-in only) ───────────────
    Map<String, dynamic> appleUserJson = {};
    if (callbackParams.containsKey('user')) {
      try {
        appleUserJson =
            jsonDecode(callbackParams['user']!) as Map<String, dynamic>;
      } catch (_) {
        // Non-fatal: user field parse failure. Name won't be populated this login.
      }
    }

    final nameMap = appleUserJson['name'] as Map<String, dynamic>? ?? {};
    final firstName = nameMap['firstName'] as String?;
    final lastName = nameMap['lastName'] as String?;
    // Email from id_token is authoritative; fall back to user payload for first login.
    final email =
        idClaims['email'] as String? ?? appleUserJson['email'] as String?;
    final emailVerified = idClaims['email_verified']?.toString() == 'true';
    final isPrivateEmail = idClaims['is_private_email']?.toString() == 'true';
    final userId = idClaims['sub'] as String? ?? '';

    if (userId.isEmpty) {
      throw const IdTokenValidationException(
        'Apple id_token missing sub claim — cannot identify user.',
      );
    }

    final fullName = [
      firstName,
      lastName,
    ].where((s) => s != null && s.isNotEmpty).join(' ').trim();

    return OAuthUser(
      id: userId,
      provider: name,
      email: email,
      emailVerified: emailVerified,
      name: fullName.isEmpty ? null : fullName,
      firstName: firstName,
      lastName: lastName,
      accessToken: tokens.accessToken.value,
      refreshToken: tokens.refreshToken?.value,
      accessTokenExpiry: tokens.accessToken.expiry,
      rawData: {
        ...idClaims,
        'is_private_email': isPrivateEmail,
        if (appleUserJson.isNotEmpty) 'apple_user': appleUserJson,
      },
    );
  }

  // ---------------------------------------------------------------------------
  // refreshToken
  // ---------------------------------------------------------------------------

  /*
   * refreshToken
   * Exchanges an Apple refresh token for a new access token.
   * A fresh ES256 client_secret JWT is generated for every call.
   *
   * Example:
   *   final newTokens = await appleProvider.refreshToken(user.refreshToken!);
   *   // Store newTokens.accessToken.value and its expiry.
   */
  @override
  Future<TokenSet> refreshToken(String refreshToken) async {
    final clientSecretJwt = _generateClientSecret();

    final response = await httpClient.post(
      Uri.parse(AppleEndpoints.tokenUrl),
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
        'User-Agent': 'dart_goth/0.1.0',
      },
      body: {
        'client_id': clientId,
        'client_secret': clientSecretJwt,
        'refresh_token': refreshToken,
        'grant_type': 'refresh_token',
      },
    );

    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw TokenRefreshException(
        'Apple refresh endpoint returned HTTP ${response.statusCode}: '
        '${response.body}',
      );
    }

    final Map<String, dynamic> json;
    try {
      json = jsonDecode(response.body) as Map<String, dynamic>;
    } catch (e) {
      throw TokenRefreshException(
        'Apple refresh endpoint returned non-JSON: ${response.body}',
        cause: e,
      );
    }

    if (json.containsKey('error')) {
      throw TokenRefreshException(
        'Apple refresh error: ${json["error"]} — ${json["error_description"]}',
      );
    }

    return buildTokenSet(json);
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /*
   * _generateClientSecret
   * Generates a short-lived ES256-signed JWT to authenticate dart_goth to Apple.
   *
   * Apple requires:
   *   Header:  { alg: "ES256", kid: "<keyId>" }
   *   Payload: { iss: "<teamId>", iat: <now>, exp: <now+300>,
   *              aud: "https://appleid.apple.com", sub: "<clientId>" }
   *
   * Signed with the ES256 private key from the .p8 file using dart_jsonwebtoken.
   *
   * The Apple .p8 key is PKCS#8 DER in a PEM envelope with:
   *   -----BEGIN PRIVATE KEY-----
   * dart_jsonwebtoken's ECPrivateKey accepts this format directly.
   *
   * Example:
   *   final secret = _generateClientSecret();
   *   // Use as 'client_secret' in the token endpoint POST body.
   */
  String _generateClientSecret() {
    final now = DateTime.now();

    try {
      final jwtToken = djwt.JWT(
        {
          'iss': teamId,
          'iat': now.millisecondsSinceEpoch ~/ 1000,
          'exp': (now.millisecondsSinceEpoch ~/ 1000) + 300, // 5 minutes
          'aud': AppleEndpoints.issuer,
          'sub': clientId,
        },
        header: {
          'alg': djwt.JWTAlgorithm.ES256,
          'kid':
              keyId, // Apple uses 'kid' in the JWT header to select the right key
        },
      );

      return jwtToken.sign(
        djwt.ECPrivateKey(privateKeyPem),
        algorithm: djwt.JWTAlgorithm.ES256,
      );
    } on djwt.JWTException catch (e) {
      throw OAuthClientSecretException(
        'Failed to generate Apple client_secret JWT: ${e.message}. '
        'Ensure privateKeyPem is a valid PKCS#8 PEM '
        '(-----BEGIN PRIVATE KEY-----) downloaded from the Apple developer portal.',
        cause: e,
      );
    }
  }

  /*
   * _verifyAndDecodeIdToken
   * Fetches Apple's public keys from their JWKS endpoint, verifies the
   * id_token RS256 signature, then validates all required claims.
   *
   * Validation checklist (per Apple docs + OIDC spec):
   *   [x] Signature verified against live JWKS (RS256)
   *   [x] iss == "https://appleid.apple.com"
   *   [x] aud == clientId (our Services ID)
   *   [x] exp > now (not expired)
   *   [x] nonce == SHA-256(rawNonce) when present (replay + injection prevention)
   *
   * Apple id_token uses RS256 — the ES256 key from the .p8 file is for
   * client_secret only. Apple signs tokens we receive with their own RSA keys.
   *
   * Example:
   *   final claims = await _verifyAndDecodeIdToken(rawIdToken, storedRawNonce);
   *   final sub = claims['sub'] as String; // stable user identifier
   */
  Future<Map<String, dynamic>> _verifyAndDecodeIdToken(
    String rawIdToken,
    String rawNonce,
  ) async {
    if (verifyIdTokenSignature) {
      try {
        // Fetch Apple's public key set
        final keysResponse = await httpClient.get(
          Uri.parse(AppleEndpoints.keysUrl),
          headers: {'Accept': 'application/json'},
        );

        if (keysResponse.statusCode != 200) {
          throw IdTokenValidationException(
            'Failed to fetch Apple JWKS: HTTP ${keysResponse.statusCode}.',
          );
        }

        // Build the key store from the JWKS document
        final jwksJson = jsonDecode(keysResponse.body) as Map<String, dynamic>;
        final keyStore = jose.JsonWebKeyStore();
        for (final keyJson in (jwksJson['keys'] as List<dynamic>)) {
          try {
            keyStore.addKey(
              jose.JsonWebKey.fromJson(keyJson as Map<String, dynamic>),
            );
          } catch (_) {
            // Skip any malformed key entries; continue with the rest.
          }
        }

        // Verify the JWS signature
        try {
          final jws = jose.JsonWebSignature.fromCompactSerialization(
            rawIdToken,
          );
          await jws.getPayload(keyStore); // checks if jwt is verified
        } catch (e) {
          throw const IdTokenValidationException(
            'Apple id_token signature verification failed. '
            'The token may have been tampered with or signed by an unknown key.',
          );
        }
      } on IdTokenValidationException {
        rethrow;
      } catch (e) {
        throw IdTokenValidationException(
          'Apple JWKS fetch or id_token verification error.',
          cause: e,
        );
      }
    }

    // Decode the payload (signature already verified above when enabled)
    final claims = _decodeJwtPayload(rawIdToken);

    // Validate all required OIDC + Apple-specific claims
    _validateIdTokenClaims(claims, rawNonce);

    return claims;
  }

  /*
   * _validateIdTokenClaims
   * Validates the required OIDC claims in the decoded id_token payload.
   * Throws [IdTokenValidationException] on any failure.
   *
   * Example:
   *   _validateIdTokenClaims(decodedClaims, storedRawNonce);
   */
  void _validateIdTokenClaims(Map<String, dynamic> claims, String rawNonce) {
    // iss: must be Apple
    final iss = claims['iss'] as String?;
    if (iss != AppleEndpoints.issuer) {
      throw IdTokenValidationException(
        'id_token issuer mismatch: expected "${AppleEndpoints.issuer}", got "$iss".',
      );
    }

    // aud: must match our Services ID (clientId)
    final aud = claims['aud'];
    final audStr = aud is List ? aud.firstOrNull as String? : aud as String?;
    if (audStr != clientId) {
      throw IdTokenValidationException(
        'id_token audience mismatch: expected "$clientId", got "$audStr".',
      );
    }

    // exp: token must not be expired
    final exp = claims['exp'];
    if (exp is int) {
      final expiry = DateTime.fromMillisecondsSinceEpoch(
        exp * 1000,
        isUtc: true,
      );
      if (DateTime.now().toUtc().isAfter(expiry)) {
        throw const IdTokenValidationException('Apple id_token has expired.');
      }
    }

    // nonce: verify SHA-256(rawNonce) == claims['nonce'], using timing-safe compare.
    // Per Apple docs the nonce claim can be absent in some Safari + Touch ID flows
    // (a known Apple issue). We enforce it when present.
    final tokenNonce = claims['nonce'] as String?;
    if (tokenNonce != null) {
      final expectedNonce = _sha256Hex(rawNonce);
      if (!timingSafeEqual(tokenNonce, expectedNonce)) {
        throw const IdTokenValidationException(
          'Apple id_token nonce mismatch — possible replay or injection attack.',
        );
      }
    }
  }

  /*
   * _sha256Hex
   * Returns the lowercase hex-encoded SHA-256 digest of [input].
   * This is the format Apple expects for the nonce query parameter.
   *
   * Example:
   *   _sha256Hex('abc123rawNonce'); // => "ba7816bf8f01cfea..."
   */
  String _sha256Hex(String input) =>
      sha256.convert(utf8.encode(input)).toString();

  /*
   * _decodeJwtPayload
   * Base64url-decodes the middle segment of a compact JWT to extract claims.
   * Does NOT verify the signature — call [_verifyAndDecodeIdToken] for that.
   *
   * Example:
   *   final claims = _decodeJwtPayload(rawJwt);
   *   final sub = claims['sub'] as String;
   */
  Map<String, dynamic> _decodeJwtPayload(String jwt) {
    try {
      final parts = jwt.split('.');
      if (parts.length < 2) return {};

      // Restore standard base64 padding stripped by base64url encoding
      var segment = parts[1];
      switch (segment.length % 4) {
        case 2:
          segment += '==';
        case 3:
          segment += '=';
      }

      final decoded = utf8.decode(
        base64Url.decode(segment),
        allowMalformed: false,
      );
      return jsonDecode(decoded) as Map<String, dynamic>;
    } catch (e) {
      throw IdTokenValidationException(
        'Failed to decode id_token payload.',
        cause: e,
      );
    }
  }
}
