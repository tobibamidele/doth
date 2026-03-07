// lib/src/adapters/shelf_adapter.dart

/*
 * ShelfAdapter
 * Integrates dart_goth with the `shelf` web framework (and by extension
 * shelf-based frameworks: dart_frog, shelf_router, angel3, etc.).
 *
 * Usage — add these two routes to your shelf Router:
 *
 *   import 'package:dart_goth/dart_goth.dart';
 *   import 'package:dart_goth/shelf_adapter.dart';
 *   import 'package:shelf_router/shelf_router.dart';
 *   import 'package:shelf/shelf.dart';
 *
 *   void main() {
 *     Doth.use([
 *       GitHubProvider(clientId: '...', clientSecret: '...', redirectUri: '...'),
 *     ]);
 *
 *     final router = Router()
 *       ..get('/auth/<provider>', ShelfAdapter.beginAuthHandler)
 *       ..get('/auth/<provider>/callback', ShelfAdapter.callbackHandler(
 *         onSuccess: (user, request) =>
 *           Response.ok('Hello ${user.name}'),
 *         onError: (e, request) =>
 *           Response.forbidden(e.toString()),
 *       ));
 *
 *     runZoned(() => shelf_io.serve(router, 'localhost', 8080));
 *   }
 */

// ignore: depend_on_referenced_packages
import 'package:shelf/shelf.dart';

import '../core/provider.dart';
import '../core/registry.dart';

/// Signature for the success callback invoked after a user authenticates.
typedef OnAuthSuccess =
    Future<Response> Function(OAuthUser user, Request request);

/// Signature for the error callback invoked when auth fails.
typedef OnAuthError =
    Future<Response> Function(OAuthException error, Request request);

/// Shelf middleware/handler helpers for dart_goth.
class ShelfAdapter {
  ShelfAdapter._();

  /*
   * beginAuthHandler
   * A shelf [Handler] that initiates the OAuth flow for the named provider.
   * The provider name is extracted from the URL path segment `<provider>`.
   *
   * Route: GET /auth/<provider>
   *
   * Example:
   *   router.get('/auth/<provider>', ShelfAdapter.beginAuthHandler);
   */
  static Future<Response> beginAuthHandler(Request request) async {
    final providerName = _extractProvider(request);
    if (providerName == null) {
      return Response.badRequest(body: 'Missing provider name in URL.');
    }

    try {
      final provider = Doth.get(providerName);
      final session = await provider.beginAuth(
        stateStore: Doth.stateStore,
        scopes: _extractScopes(request),
      );
      return Response.found(session.authorizationUrl);
    } on ProviderNotFoundException catch (e) {
      return Response.notFound(e.message);
    } catch (e) {
      return Response.internalServerError(body: 'Auth init failed: $e');
    }
  }

  /*
   * callbackHandler
   * Returns a shelf [Handler] that completes the OAuth flow.
   * Calls [onSuccess] with the resolved [OAuthUser] on success,
   * or [onError] on any [OAuthException].
   *
   * Route: GET /auth/<provider>/callback
   *
   * Example:
   *   router.get('/auth/<provider>/callback', ShelfAdapter.callbackHandler(
   *     onSuccess: (user, _) async {
   *       // Set your session cookie, create DB record, etc.
   *       return Response.ok('Welcome ${user.name}!');
   *     },
   *     onError: (e, _) async => Response.forbidden(e.message),
   *   ));
   */
  static Handler callbackHandler({
    required OnAuthSuccess onSuccess,
    required OnAuthError onError,
    StateStore? stateStore,
  }) {
    return (Request request) async {
      final providerName = _extractProvider(request);
      if (providerName == null) {
        return Response.badRequest(body: 'Missing provider name in URL.');
      }

      try {
        final provider = Doth.get(providerName);
        final params = request.url.queryParameters;

        final user = await provider.completeAuth(
          callbackParams: params,
          stateStore: stateStore ?? Doth.stateStore,
        );

        return onSuccess(user, request);
      } on ProviderNotFoundException catch (e) {
        return Response.notFound(e.message);
      } on OAuthException catch (e) {
        return onError(e, request);
      } catch (e) {
        return Response.internalServerError(body: 'Callback failed: $e');
      }
    };
  }

  /*
   * postCallbackHandler
   * Like [callbackHandler] but reads params from the POST body.
   * Required for Apple Sign-In which uses `response_mode=form_post`.
   *
   * Route: POST /auth/<provider>/callback
   *
   * Example:
   *   router.post('/auth/apple/callback',
   *     ShelfAdapter.postCallbackHandler(onSuccess: ..., onError: ...));
   */
  static Handler postCallbackHandler({
    required OnAuthSuccess onSuccess,
    required OnAuthError onError,
    StateStore? stateStore,
  }) {
    return (Request request) async {
      final providerName = _extractProvider(request);
      if (providerName == null) {
        return Response.badRequest(body: 'Missing provider name in URL.');
      }

      try {
        final provider = Doth.get(providerName);

        // Parse application/x-www-form-urlencoded body
        final body = await request.readAsString();
        final params = Uri.splitQueryString(body);

        final user = await provider.completeAuth(
          callbackParams: params,
          stateStore: stateStore ?? Doth.stateStore,
        );

        return onSuccess(user, request);
      } on ProviderNotFoundException catch (e) {
        return Response.notFound(e.message);
      } on OAuthException catch (e) {
        return onError(e, request);
      } catch (e) {
        return Response.internalServerError(body: 'Callback failed: $e');
      }
    };
  }

  // ---- Private helpers ----

  /// Extracts the provider name from:
  /// 1. Path parameter `<provider>` (shelf_router style)
  /// 2. Query parameter `?provider=github`
  static String? _extractProvider(Request request) {
    // shelf_router stores path params in request context
    final params = request.context['shelf_router/params'];
    if (params is Map) {
      final v = params['provider'];
      if (v is String && v.isNotEmpty) return v.toLowerCase();
    }
    return request.url.queryParameters['provider']?.toLowerCase();
  }

  /// Extracts optional additional scopes from `?scopes=read:user,email`
  static List<String> _extractScopes(Request request) {
    final raw = request.url.queryParameters['scopes'] ?? '';
    return raw.isEmpty
        ? const []
        : raw.split(',').map((s) => s.trim()).toList();
  }
}
