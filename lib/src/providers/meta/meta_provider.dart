// lib/src/providers/meta/meta_provider.dart

/*
 * MetaProvider
 * OAuth2 provider for Meta (Facebook Login).
 * Uses the Authorization Code flow with PKCE.
 * Docs: https://developers.facebook.com/docs/facebook-login/guides/advanced/manual-flow
 *
 * Example:
 *   DartGoth.use([
 *     MetaProvider(
 *       clientId: Platform.environment['META_APP_ID']!,
 *       clientSecret: Platform.environment['META_APP_SECRET']!,
 *       redirectUri: 'https://yourapp.com/auth/meta/callback',
 *     ),
 *   ]);
 */

import '../../core/provider.dart';

class MetaEndpoints {
  static const String authUrl = 'https://www.facebook.com/v19.0/dialog/oauth';
  static const String tokenUrl =
      'https://graph.facebook.com/v19.0/oauth/access_token';

  /// Graph API user endpoint. Fields are customizable.
  static const String userInfoBaseUrl = 'https://graph.facebook.com/v19.0/me';
}

class MetaProvider extends OAuthProvider {
  /// Graph API fields to request. Customize to get more/fewer fields.
  final List<String> fields;

  MetaProvider({
    required super.clientId,
    required super.clientSecret,
    required super.redirectUri,
    List<String> scopes = const ['public_profile', 'email'],
    this.fields = const [
      'id',
      'name',
      'first_name',
      'last_name',
      'email',
      'picture.type(large)',
      'link',
    ],
    super.httpClient,
  }) : super(defaultScopes: scopes, usePkce: true);

  @override
  String get name => 'meta';

  @override
  String get displayName => 'Meta';

  /*
   * beginAuth
   * Builds the Meta/Facebook authorization URL with PKCE and state.
   *
   * Example:
   *   final session = await metaProvider.beginAuth(stateStore: store);
   *   return Response.found(session.authorizationUrl);
   */
  @override
  Future<OAuthSession> beginAuth({
    required StateStore stateStore,
    List<String> scopes = const [],
    AuthConfig config = const AuthConfig(),
  }) async {
    final state = generateState();
    final pkce = PkceChallenge.generate();
    final allScopes = mergeScopes([...scopes, ...config.additionalScopes]);

    await stateStore.save(
      state,
      StateEntry(
        providerName: name,
        expiry: DateTime.now().add(const Duration(minutes: 10)),
        pkceVerifier: pkce.verifier,
      ),
    );

    final url = Uri.parse(MetaEndpoints.authUrl).replace(
      queryParameters: {
        'client_id': clientId,
        'redirect_uri': redirectUri,
        'scope': allScopes.join(','),
        'state': state,
        'response_type': 'code',
        'code_challenge': pkce.challenge,
        'code_challenge_method': pkce.method,
        ...config.extraParams,
      },
    );

    return OAuthSession(
      authorizationUrl: url.toString(),
      state: state,
      providerName: name,
      pkceChallenge: pkce.challenge,
    );
  }

  /*
   * completeAuth
   * Handles the Meta callback. Exchanges the code, then fetches the user
   * profile from the Graph API.
   *
   * Example:
   *   final user = await metaProvider.completeAuth(
   *     callbackParams: request.uri.queryParameters,
   *     stateStore: store,
   *   );
   *   print(user.name); // Full name from Facebook profile
   */
  @override
  Future<OAuthUser> completeAuth({
    required Map<String, String> callbackParams,
    required StateStore stateStore,
  }) async {
    checkCallbackForErrors(callbackParams);

    final callbackState = callbackParams['state'];
    if (callbackState == null) {
      throw const InvalidStateException('Missing state in Meta callback.');
    }

    final entry = await validateAndConsumeState(callbackState, stateStore);
    final code = callbackParams['code'];
    if (code == null) {
      throw const TokenExchangeException('Missing code in Meta callback.');
    }

    final tokenJson = await postTokenEndpoint(MetaEndpoints.tokenUrl, {
      'client_id': clientId,
      'client_secret': clientSecret!,
      'code': code,
      'redirect_uri': redirectUri,
      if (entry.pkceVerifier != null) 'code_verifier': entry.pkceVerifier!,
    });

    final tokens = buildTokenSet(tokenJson);
    final accessToken = tokens.accessToken.value;

    // Fetch user profile from Graph API
    final userInfoUrl = Uri.parse(MetaEndpoints.userInfoBaseUrl).replace(
      queryParameters: {
        'fields': fields.join(','),
        'access_token': accessToken,
      },
    );

    final profile = await getWithBearerToken(
      userInfoUrl.toString(),
      accessToken,
    );

    // Extract profile picture URL
    String? avatarUrl;
    final picture = profile['picture'];
    if (picture is Map) {
      final data = picture['data'] as Map?;
      avatarUrl = data?['url'] as String?;
    }

    return OAuthUser(
      id: profile['id'] as String,
      provider: name,
      email: profile['email'] as String?,
      emailVerified: false, // Meta doesn't expose email verification status
      name: profile['name'] as String?,
      firstName: profile['first_name'] as String?,
      lastName: profile['last_name'] as String?,
      avatarUrl: avatarUrl,
      profileUrl: profile['link'] as String?,
      accessToken: accessToken,
      refreshToken: tokens.refreshToken?.value,
      accessTokenExpiry: tokens.accessToken.expiry,
      rawData: profile,
    );
  }

  /*
   * refreshToken
   * Meta (Facebook) long-lived tokens don't use a traditional refresh_token.
   * Instead, you exchange a short-lived token for a long-lived one.
   * This method implements that exchange.
   *
   * Example:
   *   final newTokens = await metaProvider.refreshToken(shortLivedToken);
   */
  @override
  Future<TokenSet> refreshToken(String refreshToken) async {
    final json = await postTokenEndpoint(
      'https://graph.facebook.com/v19.0/oauth/access_token',
      {
        'grant_type': 'fb_exchange_token',
        'client_id': clientId,
        'client_secret': clientSecret!,
        'fb_exchange_token': refreshToken,
      },
    );
    return buildTokenSet(json);
  }
}
