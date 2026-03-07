// lib/src/providers/discord/discord_provider.dart

/*
 * DiscordProvider
 * OAuth2 provider for Discord.
 * Docs: https://discord.com/developers/docs/topics/oauth2
 *
 * Example:
 *   DartGoth.use([
 *     DiscordProvider(
 *       clientId: Platform.environment['DISCORD_CLIENT_ID']!,
 *       clientSecret: Platform.environment['DISCORD_CLIENT_SECRET']!,
 *       redirectUri: 'https://yourapp.com/auth/discord/callback',
 *     ),
 *   ]);
 */

import '../../core/provider.dart';

class DiscordEndpoints {
  static const String authUrl = 'https://discord.com/api/oauth2/authorize';
  static const String tokenUrl = 'https://discord.com/api/oauth2/token';
  static const String userInfoUrl = 'https://discord.com/api/users/@me';
  static const String avatarBaseUrl = 'https://cdn.discordapp.com/avatars';
}

class DiscordProvider extends OAuthProvider {
  DiscordProvider({
    required super.clientId,
    required super.clientSecret,
    required super.redirectUri,
    List<String> scopes = const ['identify', 'email'],
    super.httpClient,
  }) : super(defaultScopes: scopes, usePkce: true);

  @override
  String get name => 'discord';

  @override
  String get displayName => 'Discord';

  /*
   * beginAuth
   * Builds Discord authorization URL. Set prompt='none' in [AuthConfig.extraParams]
   * to skip the authorization screen for previously authorized users.
   *
   * Example:
   *   final session = await discordProvider.beginAuth(
   *     stateStore: store,
   *     config: AuthConfig(extraParams: {'prompt': 'none'}),
   *   );
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

    final url = Uri.parse(DiscordEndpoints.authUrl).replace(
      queryParameters: {
        'client_id': clientId,
        'redirect_uri': redirectUri,
        'response_type': 'code',
        'scope': allScopes.join(' '),
        'state': state,
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
   * Exchanges the code and fetches the Discord user object.
   * Avatar URL is constructed from the Discord CDN using the user's avatar hash.
   *
   * Example:
   *   final user = await discordProvider.completeAuth(
   *     callbackParams: request.uri.queryParameters,
   *     stateStore: store,
   *   );
   */
  @override
  Future<OAuthUser> completeAuth({
    required Map<String, String> callbackParams,
    required StateStore stateStore,
  }) async {
    checkCallbackForErrors(callbackParams);

    final callbackState = callbackParams['state'];
    if (callbackState == null) {
      throw const InvalidStateException();
    }

    final entry = await validateAndConsumeState(callbackState, stateStore);
    final code = callbackParams['code'];
    if (code == null) {
      throw const TokenExchangeException('Missing code.');
    }

    final tokenJson = await postTokenEndpoint(DiscordEndpoints.tokenUrl, {
      'client_id': clientId,
      'client_secret': clientSecret!,
      'code': code,
      'redirect_uri': redirectUri,
      'grant_type': 'authorization_code',
      if (entry.pkceVerifier != null) 'code_verifier': entry.pkceVerifier!,
    });

    final tokens = buildTokenSet(tokenJson);
    final accessToken = tokens.accessToken.value;

    final profile = await getWithBearerToken(
      DiscordEndpoints.userInfoUrl,
      accessToken,
    );

    final userId = profile['id'] as String;
    final avatarHash = profile['avatar'] as String?;
    String? avatarUrl;
    if (avatarHash != null) {
      final ext = avatarHash.startsWith('a_') ? 'gif' : 'png';
      avatarUrl =
          '${DiscordEndpoints.avatarBaseUrl}/$userId/$avatarHash.$ext?size=256';
    }

    return OAuthUser(
      id: userId,
      provider: name,
      email: profile['email'] as String?,
      emailVerified: profile['verified'] as bool? ?? false,
      name: profile['global_name'] as String? ?? profile['username'] as String?,
      username: profile['username'] as String?,
      avatarUrl: avatarUrl,
      accessToken: accessToken,
      refreshToken: tokens.refreshToken?.value,
      accessTokenExpiry: tokens.accessToken.expiry,
      rawData: profile,
    );
  }

  /*
   * refreshToken
   * Exchanges a Discord refresh token for a new access token.
   *
   * Example:
   *   final newTokens = await discordProvider.refreshToken(user.refreshToken!);
   */
  @override
  Future<TokenSet> refreshToken(String refreshToken) async {
    final json = await postTokenEndpoint(DiscordEndpoints.tokenUrl, {
      'client_id': clientId,
      'client_secret': clientSecret!,
      'grant_type': 'refresh_token',
      'refresh_token': refreshToken,
    });
    return buildTokenSet(json);
  }
}
