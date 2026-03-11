// lib/src/core/exceptions.dart

/*
 * OAuthException
 * Base exception for all doth errors.
 * Sub-types allow callers to handle specific failure modes.
 *
 * Example:
 *   try {
 *     final user = await goth.completeAuth(request);
 *   } on InvalidStateException {
 *     return Response.forbidden('CSRF check failed');
 *   } on TokenExchangeException catch (e) {
 *     return Response.internalServerError(body: e.message);
 *   }
 */

/// Base class for all doth exceptions.
sealed class OAuthException implements Exception {
  final String message;
  final Object? cause;

  const OAuthException(this.message, {this.cause});

  @override
  String toString() =>
      'OAuthException($runtimeType): $message'
      '${cause != null ? '\nCaused by: $cause' : ''}';
}

/// The OAuth `state` parameter was missing, unknown, or already consumed.
/// This indicates a CSRF attack attempt or an expired flow.
final class InvalidStateException extends OAuthException {
  const InvalidStateException([
    String message = 'Invalid or expired OAuth state parameter.',
    Object? cause,
  ]) : super(message, cause: cause);
}

/// The provider returned an error code in the callback (e.g. `access_denied`).
final class ProviderErrorException extends OAuthException {
  /// The error code returned by the provider (e.g. `access_denied`).
  final String errorCode;

  /// Optional human-readable description from the provider.
  final String? errorDescription;

  const ProviderErrorException({required this.errorCode, this.errorDescription})
    : super('Provider returned error: $errorCode');
}

/// The authorization code → token exchange failed.
final class TokenExchangeException extends OAuthException {
  /// HTTP status code returned by the token endpoint, if available.
  final int? statusCode;

  const TokenExchangeException(super.message, {this.statusCode, super.cause});
}

/// Fetching the user profile from the provider's API failed.
final class UserFetchException extends OAuthException {
  final int? statusCode;

  const UserFetchException(super.message, {this.statusCode, super.cause});
}

/// The named provider is not registered with Doth.
final class ProviderNotFoundException extends OAuthException {
  final String providerName;

  const ProviderNotFoundException(this.providerName)
    : super('Provider not registered: $providerName');
}

/// A refresh token operation failed.
final class TokenRefreshException extends OAuthException {
  const TokenRefreshException(super.message, {super.cause});
}

/// JWT / ID token validation failed (signature, expiry, audience, etc.).
final class IdTokenValidationException extends OAuthException {
  const IdTokenValidationException(super.message, {super.cause});
}

/// A client secret exception occured. Eg, failed to sign jwt for apple provider.
final class OAuthClientSecretException extends OAuthException {
  const OAuthClientSecretException(super.message, {super.cause});
}
