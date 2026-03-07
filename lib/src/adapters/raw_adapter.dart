// lib/src/adapters/raw_adapter.dart

/*
 * RawAdapter
 * Integrates dart_goth with raw `dart:io` HttpServer, requiring
 * no web framework at all. Compatible with any custom server.
 *
 * Example:
 *   final server = await HttpServer.bind('localhost', 8080);
 *   await for (final request in server) {
 *     await RawAdapter.handle(request, stateStore: DartGoth.stateStore);
 *   }
 */

import 'dart:io';

import '../core/exceptions.dart';
import '../core/registry.dart';
import '../core/state_store.dart';
import '../core/user.dart';

/// Callback type used by [RawAdapter.handle].
typedef RawAuthSuccessCallback =
    Future<void> Function(OAuthUser user, HttpRequest request);

typedef RawAuthErrorCallback =
    Future<void> Function(OAuthException error, HttpRequest request);

/// A framework-agnostic adapter for dart_goth using raw `dart:io`.
class RawAdapter {
  RawAdapter._();

  /*
   * handle
   * Routes an incoming [HttpRequest] to either [beginAuth] or [completeAuth]
   * based on the path. The path must follow the pattern:
   *   GET /auth/{provider}           → begin flow
   *   GET /auth/{provider}/callback  → complete flow
   *   POST /auth/{provider}/callback → complete flow (form_post, e.g. Apple)
   *
   * Example:
   *   await for (final req in server) {
   *     await RawAdapter.handle(req,
   *       onSuccess: (user, _) async {
   *         final response = req.response;
   *         response.write('Hello ${user.name}');
   *         await response.close();
   *       },
   *       onError: (e, req) async {
   *         req.response.statusCode = 403;
   *         await req.response.close();
   *       },
   *     );
   *   }
   */
  static Future<void> handle(
    HttpRequest request, {
    required RawAuthSuccessCallback onSuccess,
    required RawAuthErrorCallback onError,
    StateStore? stateStore,
    String pathPrefix = '/auth',
  }) async {
    final store = stateStore ?? Doth.stateStore;
    final path = request.uri.path;
    final segments = path
        .replaceFirst(pathPrefix, '')
        .split('/')
        .where((s) => s.isNotEmpty)
        .toList();

    if (segments.isEmpty) {
      request.response
        ..statusCode = HttpStatus.badRequest
        ..write('Provider not specified.');
      await request.response.close();
      return;
    }

    final providerName = segments[0].toLowerCase();
    final isCallback = segments.length >= 2 && segments[1] == 'callback';

    try {
      final provider = Doth.get(providerName);

      if (!isCallback) {
        // Begin flow
        final session = await provider.beginAuth(stateStore: store);
        request.response
          ..statusCode = HttpStatus.found
          ..headers.set(HttpHeaders.locationHeader, session.authorizationUrl);
        await request.response.close();
      } else {
        // Complete flow
        Map<String, String> params;

        if (request.method == 'POST') {
          // Read form body (Apple Sign-In form_post)
          final body = await _readBody(request);
          params = Uri.splitQueryString(body);
        } else {
          params = request.uri.queryParameters;
        }

        final user = await provider.completeAuth(
          callbackParams: params,
          stateStore: store,
        );

        await onSuccess(user, request);
      }
    } on ProviderNotFoundException catch (e) {
      request.response
        ..statusCode = HttpStatus.notFound
        ..write(e.message);
      await request.response.close();
    } on OAuthException catch (e) {
      await onError(e, request);
    } catch (e) {
      request.response
        ..statusCode = HttpStatus.internalServerError
        ..write('Internal error: $e');
      await request.response.close();
    }
  }

  static Future<String> _readBody(HttpRequest request) async {
    final buffer = StringBuffer();
    await for (final chunk in request) {
      buffer.write(String.fromCharCodes(chunk));
    }
    return buffer.toString();
  }
}
