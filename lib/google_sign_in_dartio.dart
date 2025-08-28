library google_sign_in_dartio;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';
import 'package:google_sign_in_platform_interface/google_sign_in_platform_interface.dart'
    as platform;
import 'package:http/http.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:url_launcher/url_launcher.dart';

part 'src/code_exchange_sign_in.dart';
part 'src/common.dart';
part 'src/crypto.dart';
part 'src/data_storage.dart';
part 'src/token_sign_in.dart';

/// Signature used by the [_codeExchangeSignIn] to allow opening a browser window
/// in a platform specific way.
typedef UrlPresenter = void Function(Uri uri);

/// Implementation of the google_sign_in plugin in pure dart.
class GoogleSignInDart extends platform.GoogleSignInPlatform {
  GoogleSignInDart._({
    required DataStorage storage,
    required String clientId,
    required UrlPresenter presenter,
    String? exchangeEndpoint,
    String? appRedirectUrl,
    int? port,
  })  : _storage = storage,
        _clientId = clientId,
        _appRedirectUrl = appRedirectUrl,
        presenter = presenter,
        _port = port,
        _exchangeEndpoint = exchangeEndpoint;

  /// Registers this implementation as default implementation for GoogleSignIn
  ///
  /// Your application should provide a [storage] implementation that can store
  /// the tokens is a secure, long-lived location that is accessible between
  /// different invocations of your application.
  static Future<void> register({
    required String clientId,
    String? exchangeEndpoint,
    Store? store,
    UrlPresenter? presenter,
    int? port,
    String? appRedirectUrl,
  }) async {
    presenter ??= (Uri uri) => launchUrl(uri);

    if (store == null) {
      WidgetsFlutterBinding.ensureInitialized();
      final SharedPreferences _preferences =
          await SharedPreferences.getInstance();
      store = _SharedPreferencesStore(_preferences);
    }

    final DataStorage storage = DataStorage._(store: store, clientId: clientId);

    // If tokenExchangeEndpoint is removed in a session after the user was
    // logged in, we need to clear the refresh token since we can non longer use
    // it.
    if (storage.refreshToken != null && exchangeEndpoint == null) {
      storage.refreshToken = null;
    }

    platform.GoogleSignInPlatform.instance = GoogleSignInDart._(
      presenter: presenter,
      storage: storage,
      exchangeEndpoint: exchangeEndpoint,
      clientId: clientId,
      port: port,
      appRedirectUrl: appRedirectUrl,
    );
  }

  final String? _exchangeEndpoint;
  final String _clientId;
  final String? _appRedirectUrl;
  final DataStorage _storage;
  final int? _port;

  late List<String> _scopes;
  String? _hostedDomain;

  String? _accessToken;
  String? _idToken;
  String? _refreshToken;
  DateTime? _expiresAt;

  /// Used by the sign in flow to allow opening of a browser in a platform
  /// specific way.
  ///
  /// You can open the link in a in-app WebView or you can open it in the system
  /// browser
  UrlPresenter presenter;

  @override
  Future<void> init(platform.InitParameters params) async {
    assert(params.clientId == null || params.clientId == _clientId,
        'ClientID (${params.clientId}) does not match the one used to register the plugin $_clientId.');

    if (params.hostedDomain != null) {
      _hostedDomain = params.hostedDomain;
    }

    // Default scopes if none provided
    _scopes = const <String>['openid', 'email', 'profile'];
    _initFromStore();
  }

  @override
  Future<platform.AuthenticationResults?>? attemptLightweightAuthentication(
      platform.AttemptLightweightAuthenticationParameters params) async {
    // This method attempts to sign in without explicit user intent
    // We'll try to use existing tokens if available, similar to signInSilently
    try {
      if (_haveValidToken) {
        final userData = _storage.userData;
        if (userData != null) {
          return platform.AuthenticationResults(
            user: userData,
            authenticationTokens: platform.AuthenticationTokenData(
              idToken: _idToken,
            ),
          );
        }
      } else if (_refreshToken != null) {
        try {
          await _doTokenRefresh();
          final userData = _storage.userData;
          if (userData != null) {
            return platform.AuthenticationResults(
              user: userData,
              authenticationTokens: platform.AuthenticationTokenData(
                idToken: _idToken,
              ),
            );
          }
        } catch (e) {
          // Silent failure for lightweight authentication
          return null;
        }
      }
      return null;
    } catch (e) {
      // Silent failure for lightweight authentication
      return null;
    }
  }

  @override
  Future<platform.AuthenticationResults> authenticate(
      platform.AuthenticateParameters params) async {
    // This method signs in with explicit user intent
    // Similar to the existing signIn method but returns AuthenticationResults
    if (_haveValidToken) {
      final userData = _storage.userData;
      if (userData == null) {
        await _fetchUserProfile();
      }
      final finalUserData = _storage.userData;
      if (finalUserData == null) {
        throw platform.GoogleSignInException(
          code: platform.GoogleSignInExceptionCode.unknownError,
          description: 'Failed to fetch user profile',
        );
      }
      return platform.AuthenticationResults(
        user: finalUserData,
        authenticationTokens: platform.AuthenticationTokenData(
          idToken: _idToken,
        ),
      );
    } else {
      // Use scope hint if provided, otherwise use default scopes
      final scopesToUse =
          params.scopeHint.isNotEmpty ? params.scopeHint : _scopes;
      await _performSignIn(scopesToUse);
      final userData = _storage.userData;
      if (userData == null) {
        throw platform.GoogleSignInException(
          code: platform.GoogleSignInExceptionCode.unknownError,
          description: 'Failed to fetch user profile after sign in',
        );
      }
      return platform.AuthenticationResults(
        user: userData,
        authenticationTokens: platform.AuthenticationTokenData(
          idToken: _idToken,
        ),
      );
    }
  }

  @override
  /// Indicates whether authorization requires explicit user interaction.
  ///
  /// In general, browser-based OAuth flows may not always require user interaction,
  /// as tokens can sometimes be cached or refreshed silently without prompting the user.
  /// However, in this implementation, we always require user interaction because:
  ///   - We do not support silent token refresh or caching of tokens that would allow
  ///     re-authentication without user involvement.
  ///   - Each authentication attempt initiates a new browser-based OAuth flow.
  ///
  /// If support for silent authentication or token caching is added in the future,
  /// this method's behavior and documentation should be updated accordingly.
  @override
  bool authorizationRequiresUserInteraction() {
    return true;
  }

  @override
  Future<platform.ClientAuthorizationTokenData?>
      clientAuthorizationTokensForScopes(
          platform.ClientAuthorizationTokensForScopesParameters params) async {
    final request = params.request;

    // Check if we have valid tokens for the requested scopes
    if (_haveValidToken &&
        request.scopes.every((scope) => _storage.scopes.contains(scope))) {
      return platform.ClientAuthorizationTokenData(
        accessToken: _accessToken!,
      );
    }

    // If we don't have the required scopes and can't prompt, return null
    if (!request.promptIfUnauthorized) {
      return null;
    }

    // Check if the user matches the requested user
    if (request.userId != null || request.email != null) {
      final currentUser = _storage.userData;
      if (currentUser == null) {
        return null;
      }

      if (request.userId != null && currentUser.id != request.userId) {
        return null;
      }

      if (request.email != null && currentUser.email != request.email) {
        return null;
      }
    }

    // Request the required scopes
    try {
      await _performSignIn(request.scopes);
      if (_haveValidToken) {
        return platform.ClientAuthorizationTokenData(
          accessToken: _accessToken!,
        );
      }
    } catch (e) {
      throw platform.GoogleSignInException(
        code: platform.GoogleSignInExceptionCode.unknownError,
        description: e.toString(),
      );
    }

    return null;
  }

  @override
  Future<platform.ServerAuthorizationTokenData?>
      serverAuthorizationTokensForScopes(
          platform.ServerAuthorizationTokensForScopesParameters params) async {
    final request = params.request;

    // Check if we have valid tokens for the requested scopes
    if (_haveValidToken &&
        request.scopes.every((scope) => _storage.scopes.contains(scope))) {
      // For server authorization, we need to check if we have a server auth code
      // This implementation doesn't currently support server auth codes
      // Return null to indicate we need to prompt for authorization
      return null;
    }

    // If we can't prompt, return null
    if (!request.promptIfUnauthorized) {
      return null;
    }

    // Check if the user matches the requested user
    if (request.userId != null || request.email != null) {
      final currentUser = _storage.userData;
      if (currentUser == null) {
        return null;
      }

      if (request.userId != null && currentUser.id != request.userId) {
        return null;
      }

      if (request.email != null && currentUser.email != request.email) {
        return null;
      }
    }

    // This implementation doesn't support server authorization tokens
    // Return null to indicate the feature is not supported
    return null;
  }

  @override
  bool supportsAuthenticate() {
    // This implementation supports the authenticate method
    return true;
  }

  @override
  Future<void> signOut(platform.SignOutParams params) async {
    _storage.clearAll();
    _initFromStore();
  }

  @override
  Future<void> disconnect(platform.DisconnectParams params) async {
    await _revokeToken();
    _storage.clear();
    _initFromStore();
  }

  Future<void> _revokeToken() async {
    if (_haveValidToken) {
      final String? token = _accessToken;

      await get(
        Uri.parse('https://oauth2.googleapis.com/revoke?token=$token'),
        headers: <String, String>{
          'content-type': 'application/x-www-form-urlencoded'
        },
      );
    }
  }

  Future<void> _fetchUserProfile() async {
    if (_haveValidToken) {
      final String token = _accessToken!;
      final Response response = await get(
        Uri.parse('https://openidconnect.googleapis.com/v1/userinfo'),
        headers: <String, String>{
          'Authorization': 'Bearer $token',
        },
      );

      if (response.statusCode > 300) {
        if (response.statusCode == 401) {
          await signOut(platform.SignOutParams());
        }
        throw platform.GoogleSignInException(
          code: platform.GoogleSignInExceptionCode.unknownError,
          description: response.body,
        );
      }

      final Map<String, dynamic> result = jsonDecode(response.body);
      _storage.saveUserProfile(result);
    }
  }

  bool get _haveValidToken {
    return _expiresAt != null && DateTime.now().isBefore(_expiresAt!);
  }

  Future<void> _performSignIn(List<String> scopes) async {
    Future<Map<String, dynamic>> future;
    if (_exchangeEndpoint != null) {
      future = _codeExchangeSignIn(
        scope: scopes.join(' '),
        clientId: _clientId,
        hostedDomains: _hostedDomain,
        presenter: presenter,
        exchangeEndpoint: _exchangeEndpoint!,
        uid: _storage.id,
        appRedirectUrl: _appRedirectUrl,
      );
    } else {
      future = _tokenSignIn(
        scope: scopes.join(' '),
        clientId: _clientId,
        hostedDomains: _hostedDomain,
        presenter: presenter,
        uid: _storage.id,
        port: _port,
        appRedirectUrl: _appRedirectUrl,
      );
    }

    final Map<String, dynamic> result = await future.catchError(
      (dynamic error, StackTrace s) {
        throw platform.GoogleSignInException(
          code: platform.GoogleSignInExceptionCode.unknownError,
          description: error.toString(),
        );
      },
    );

    print("result: ${jsonEncode(result)}");
    _storage.saveResult(result);
    _initFromStore();
    await _fetchUserProfile();
  }

  Future<void> _doTokenRefresh() async {
    assert(_exchangeEndpoint != null);
    assert(_refreshToken != null);

    final Response response = await post(
      Uri.parse(_exchangeEndpoint!),
      body: json.encode(<String, String>{
        'refreshToken': _refreshToken!,
        'clientId': _clientId,
      }),
    );
    if (response.statusCode == 200) {
      final Map<String, dynamic> result =
          Map<String, dynamic>.from(jsonDecode(response.body));

      _storage.saveResult(result);
      _initFromStore();
      await _fetchUserProfile();
    } else {
      throw response.body;
    }
  }

  void _initFromStore() {
    _refreshToken = _storage.refreshToken;
    _expiresAt = _storage.expiresAt;
    _accessToken = _storage.accessToken;
    _idToken = _storage.idToken;
  }
}
