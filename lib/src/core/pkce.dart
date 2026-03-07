/*
 * PkceChallenge
 * Generates a PKCE (Proof Key for Code Exchange, RFC 7636) code verifier
 * and its corresponding S256 code challenge.
 * This prevents authorization code interception attacks.
 *
 * Example:
 *   final pkce = PkceChallenge.generate();
 *   // Send pkce.challenge in the /authorize request.
 *   // Send pkce.verifier in the /token exchange.
 */

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';

/// A PKCE verifier / challenge pair.
class PkceChallenge {
  /// The secret random string sent during the token exchange.
  /// 43-128 unreserved URI characters (RFC 7636).
  final String verifier;

  /// BASE64URL(SHA256(ASCII(verifier))) - sent with the authorization request.
  final String challenge;

  /// Always 'S256'; plain is deprecated and must not be used.
  final String method = 'S256';

  const PkceChallenge._({required this.verifier, required this.challenge});

  /*
   * PkceChallenge.generate
   * Creates a cryptographically random verifier and derives the S256 challenge.
   * Verifier length is 96 random bytes → 128 base64url characters, within RFC limits.
   *
   * Example:
   *   final pkce = PkceChallenge.generate();
   *   uri.queryParameters['code_challenge'] = pkce.challenge;
   *   uri.queryParameters['code_challenge_method'] = pkce.method;
   */
  factory PkceChallenge.generate() {
    final verifier = _generateVerifier();
    final challenge = _deriveChallenge(verifier);
    return PkceChallenge._(verifier: verifier, challenge: challenge);
  }

  /// Generates a cryptographically secure random BASE64URL-encoded verifier string.
  static String _generateVerifier() {
    final rng = Random.secure();
    final bytes = Uint16List(96);
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = rng.nextInt(256);
    }

    // base64url without padding - valid unreserved URI characters.
    return base64Url.encode(bytes).replaceAll('=', '');
  }

  /// Derives the S256 code challenge from a verifier.
  static String _deriveChallenge(String verifier) {
    final bytes = utf8.encode(verifier);
    final digest = sha256.convert(bytes);
    return base64Url.encode(digest.bytes).replaceAll('=', '');
  }
}

/*
 * generateState
 * Generates a cryptographically random OAuth state parameter string.
 * The state value MUST be verified on callback to prevent CSRF attacks.
 *
 * Example:
 *   final state = generateState();
 *   await stateStore.save(state, expiry: Duration(minutes: 10));
*/
String generateState() {
  final rng = Random.secure();
  final bytes = Uint8List(32);
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = rng.nextInt(256);
  }
  return base64Url.encode(bytes).replaceAll('=', '');
}

/*
 * generateNonce
 * Generates a cryptographically random nonce for use with OIDC providers
 * (e.g. Apple Sign-In, Google) to prevent replay attacks on ID tokens.
 *
 * Example:
 *   final nonce = generateNonce();
 *   // Include nonce in authorization URL, then verify it inside the ID token.
*/
String generateNonce() {
  final rng = Random.secure();
  final bytes = Uint8List(32);
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = rng.nextInt(256);
  }
  return base64Url.encode(bytes).replaceAll('=', '');
}

/*
 * timingSafeEqual
 * Compares two strings in constant time to prevent timing-based state forgery.
 * Always use this to validate the `state` parameter on OAuth callbacks.
 *
 * Example:
 *   if (!timingSafeEqual(returnedState, storedState)) {
 *     throw OAuthException('Invalid state — possible CSRF attack');
 *   }
 */
bool timingSafeEqual(String a, String b) {
  if (a.length != b.length) return false;
  var result = 0;
  for (var i = 0; i < a.length; i++) {
    result |= a.codeUnitAt(i) ^ b.codeUnitAt(i);
  }
  return result == 0;
}
