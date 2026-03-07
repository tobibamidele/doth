// lib/src/providers/microsoft/microsoft_provider.dart

/*
 * MicrosoftProvider
 * OAuth2 / OIDC provider for Microsoft (Azure AD / Entra ID).
 * Supports single-tenant, multi-tenant, and personal account configurations.
 * Docs: https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow
 *
 * Example:
 *   DartGoth.use([
 *     MicrosoftProvider(
 *       clientId: Platform.environment['AZURE_CLIENT_ID']!,
 *       clientSecret: Platform.environment['AZURE_CLIENT_SECRET']!,
 *       redirectUri: 'https://yourapp.com/auth/microsoft/callback',
 *       tenant: MicrosoftTenant.common,  // or a specific tenant GUID
 *     ),
 *   ]);
 */

import '../../core/provider.dart';

/// Microsoft tenant configuration.
enum MicrosoftTenant {
  /// Accepts both personal Microsoft accounts and work/school accounts.
  common('common'),

  /// Only work/school accounts (Azure AD).
  organizations('organizations'),

  /// Only personal Microsoft accounts.
  consumers('consumers');

  final String value;
  const MicrosoftTenant(this.value);
}

class MicrosoftProvider extends OAuthProvider {
  final String tenant;

  MicrosoftProvider({
    required super.clientId,
    required super.clientSecret,
    required super.redirectUri,
    MicrosoftTenant tenantType = MicrosoftTenant.common,
    String? tenantId, // Specific Azure AD tenant GUID
    List<String> scopes = const ['openid', 'profile', 'email', 'User.Read'],
    super.httpClient,
  }) : tenant = tenantId ?? tenantType.value,
       super(defaultScopes: scopes, usePkce: true);

  @override
  String get name => 'microsoft';

  @override
  String get displayName => 'Microsoft';

  String get _authUrl =>
      'https://login.microsoftonline.com/$tenant/oauth2/v2.0/authorize';
  String get _tokenUrl =>
      'https://login.microsoftonline.com/$tenant/oauth2/v2.0/token';

  /*
   * beginAuth
   * Builds the Microsoft authorization URL with PKCE.
   * Pass a tenantId for single-tenant enterprise apps.
   *
   * Example:
   *   final session = await msProvider.beginAuth(stateStore: store);
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

    final params = <String, String>{
      'client_id': clientId,
      'redirect_uri': redirectUri,
      'response_type': 'code',
      'scope': allScopes.join(' '),
      'state': state,
      'code_challenge': pkce.challenge,
      'code_challenge_method': pkce.method,
    };

    if (config.forceAccountSelection) {
      params['prompt'] = 'select_account';
    }

    params.addAll(config.extraParams);

    final url = Uri.parse(_authUrl).replace(queryParameters: params);

    return OAuthSession(
      authorizationUrl: url.toString(),
      state: state,
      providerName: name,
      pkceChallenge: pkce.challenge,
    );
  }

  /*
   * completeAuth
   * Handles the Microsoft callback, exchanges the code, fetches the user
   * from Microsoft Graph API (/me endpoint).
   *
   * Example:
   *   final user = await msProvider.completeAuth(
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

    final tokenJson = await postTokenEndpoint(_tokenUrl, {
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
      'https://graph.microsoft.com/v1.0/me',
      accessToken,
    );

    final email =
        profile['mail'] as String? ?? profile['userPrincipalName'] as String?;

    return OAuthUser(
      id: profile['id'] as String,
      provider: name,
      email: email,
      emailVerified: email != null, // Microsoft verifies work emails
      name: profile['displayName'] as String?,
      firstName: profile['givenName'] as String?,
      lastName: profile['surname'] as String?,
      username: profile['userPrincipalName'] as String?,
      accessToken: accessToken,
      refreshToken: tokens.refreshToken?.value,
      accessTokenExpiry: tokens.accessToken.expiry,
      rawData: profile,
    );
  }

  /*
   * refreshToken
   * Exchanges a Microsoft refresh token for a new access token.
   *
   * Example:
   *   final newTokens = await msProvider.refreshToken(user.refreshToken!);
   */
  @override
  Future<TokenSet> refreshToken(String refreshToken) async {
    final json = await postTokenEndpoint(_tokenUrl, {
      'client_id': clientId,
      'client_secret': clientSecret!,
      'refresh_token': refreshToken,
      'grant_type': 'refresh_token',
    });
    return buildTokenSet(json);
  }
}
