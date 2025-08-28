// Copyright 2019 The Flutter Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// ignore_for_file: public_member_api_docs

import 'dart:async';

import 'package:collection/collection.dart';
import 'package:flutter/material.dart';
import 'package:google_sign_in_platform_interface/google_sign_in_platform_interface.dart';
import 'package:google_sign_in_dartio/google_sign_in_dartio.dart';
import 'package:googleapis/gmail/v1.dart';
import 'package:googleapis/people/v1.dart';
import 'package:googleapis_auth/googleapis_auth.dart';
import 'package:html_unescape/html_unescape.dart';
import 'package:http/http.dart' as http;

import 'platform_js.dart' if (dart.library.io) 'platform_io.dart';

Future<void> main() async {
  if (isDesktop) {
    await GoogleSignInDart.register(
      // Comment out the exchange endpoint to use token-based flow for testing
      // exchangeEndpoint:
      //     'https://us-central1-flutter-sdk.cloudfunctions.net/authHandler',
      clientId:
          '233259864964-go57eg1ones74e03adlqvbtg2av6tivb.apps.googleusercontent.com',
    );
  }

  runApp(
    MaterialApp(
      title: 'Google Sign In Dart',
      home: SignInDemo(),
    ),
  );
}

class SignInDemo extends StatefulWidget {
  @override
  State createState() => SignInDemoState();
}

class SignInDemoState extends State<SignInDemo> {
  late StreamSubscription<AuthenticationEvent?> sub;
  late AuthClient _client;
  GoogleSignInUserData? _currentUser;
  String? _contactText;
  String? _emailText;

  @override
  void initState() {
    super.initState();
    _test();
  }

  Future<void> _test() async {
    try {
      // Use the new API to attempt lightweight authentication
      final result =
          await GoogleSignInPlatform.instance.attemptLightweightAuthentication(
        AttemptLightweightAuthenticationParameters(),
      );
      if (result != null) {
        print('Lightweight auth result: ${result.user.email}');
        setState(() {
          _currentUser = result.user;
        });
        await _handleGetContact();
      }
    } catch (e) {
      print('Lightweight auth failed: $e');
    }
  }

  Future<void> _handleGetContact() async {
    if (_currentUser == null) return;

    setState(() => _contactText = 'Loading contact info...');

    try {
      // Get client authorization tokens for People API
      final tokenData = await GoogleSignInPlatform.instance
          .clientAuthorizationTokensForScopes(
        ClientAuthorizationTokensForScopesParameters(
          request: AuthorizationRequestDetails(
            scopes: ['https://www.googleapis.com/auth/user.emails.read'],
            userId: _currentUser!.id,
            email: _currentUser!.email,
            promptIfUnauthorized: false,
          ),
        ),
      );

      if (tokenData != null) {
        // Create an AuthClient from the access token
        final credentials = AccessCredentials(
          AccessToken('Bearer', tokenData.accessToken,
              DateTime.now().add(Duration(hours: 1))),
          null,
          ['https://www.googleapis.com/auth/user.emails.read'],
        );
        _client = authenticatedClient(http.Client(), credentials);

        final PeopleConnectionsResource connectionsApi =
            PeopleServiceApi(_client).people.connections;

        final ListConnectionsResponse listResult = await connectionsApi.list(
          'people/me',
          requestMask_includeField: 'person.names',
        );

        String? contact;
        final List<Person>? connections = listResult.connections;
        if (connections != null && connections.isNotEmpty) {
          connections.shuffle();
          final Person? person = connections //
              .where((Person person) => person.names != null)
              .firstWhereOrNull(
            (Person person) {
              return person.names! //
                  .any((Name name) => name.displayName != null);
            },
          );

          if (person != null) {
            final Name? name = person.names!
                .firstWhereOrNull((Name name) => name.displayName != null);
            contact = name?.displayName;
          }
        }

        setState(() {
          if (contact != null) {
            _contactText = contact;
          } else {
            _contactText = 'No contacts to display.';
          }
        });
      } else {
        setState(() {
          _contactText = 'No authorization for People API.';
        });
      }
    } catch (e) {
      setState(() {
        _contactText = 'Failed to load contacts: $e';
      });
    }
  }

  Future<void> _handleGetEmail() async {
    if (_currentUser == null) return;

    setState(() => _emailText = 'Loading emails...');

    try {
      // Use the new API to request Gmail scope
      final tokenData = await GoogleSignInPlatform.instance
          .clientAuthorizationTokensForScopes(
        ClientAuthorizationTokensForScopesParameters(
          request: AuthorizationRequestDetails(
            scopes: [GmailApi.gmailReadonlyScope],
            userId: _currentUser!.id,
            email: _currentUser!.email,
            promptIfUnauthorized: true,
          ),
        ),
      );

      if (tokenData == null) {
        setState(() => _emailText = 'Gmail scope was not granted by the user.');
        return;
      }

      // Create an AuthClient from the access token
      final credentials = AccessCredentials(
        AccessToken('Bearer', tokenData.accessToken,
            DateTime.now().add(Duration(hours: 1))),
        null,
        [GmailApi.gmailReadonlyScope],
      );
      _client = authenticatedClient(http.Client(), credentials);

      final UsersMessagesResource messagesApi =
          GmailApi(_client).users.messages;

      final ListMessagesResponse listResult = await messagesApi.list('me');

      String? messageSnippet;
      if (listResult.messages != null && listResult.messages!.isNotEmpty) {
        for (Message message in listResult.messages!..shuffle()) {
          message =
              await messagesApi.get('me', '${message.id}', format: 'FULL');
          final String? snippet = message.snippet;
          if (snippet != null && snippet.trim().isNotEmpty) {
            messageSnippet = HtmlUnescape().convert(snippet);
            break;
          }
        }
      }

      setState(() {
        if (messageSnippet != null) {
          _emailText = messageSnippet;
        } else {
          _emailText = 'No emails to display.';
        }
      });
    } catch (e) {
      setState(() {
        _emailText = 'Failed to load emails: $e';
      });
    }
  }

  Future<void> _handleSignIn() async {
    try {
      // Use the new authenticate method
      final result = await GoogleSignInPlatform.instance.authenticate(
        AuthenticateParameters(scopeHint: ['email', 'profile']),
      );

      setState(() {
        _currentUser = result.user;
      });

      await _handleGetContact();
    } catch (error) {
      print('Sign in failed: $error');
    }
  }

  void _handleSignOut() {
    GoogleSignInPlatform.instance.signOut(SignOutParams());
    setState(() {
      _currentUser = null;
      _contactText = null;
      _emailText = null;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Google Sign In Dart'),
      ),
      body: Builder(
        builder: (BuildContext context) {
          final GoogleSignInUserData? currentUser = _currentUser;
          final String? contactText = _contactText;
          final String? emailText = _emailText;

          if (currentUser == null) {
            return Center(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.center,
                mainAxisAlignment: MainAxisAlignment.center,
                children: <Widget>[
                  const Text('You are not currently signed in.'),
                  const SizedBox(height: 16.0),
                  ElevatedButton(
                    onPressed: _handleSignIn,
                    child: const Text('SIGN IN'),
                  ),
                ],
              ),
            );
          }

          return ListView(
            children: <Widget>[
              ListTile(
                leading: ClipOval(
                  child: Image.network(
                    currentUser.photoUrl ??
                        'https://lh3.googleusercontent.com/a/default-user=s160-c',
                  ),
                ),
                title: Text(currentUser.displayName ?? ''),
                subtitle: Text(currentUser.email),
              ),
              if (contactText != null)
                ListTile(
                  title: Text(
                    contactText,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  subtitle: const Text('People Api'),
                ),
              if (emailText != null)
                ListTile(
                  title: Text(
                    emailText,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  subtitle: const Text('Gmail Api'),
                ),
              OverflowBar(
                children: <Widget>[
                  TextButton(
                    onPressed: _handleSignOut,
                    child: const Text('SIGN OUT'),
                  ),
                  TextButton(
                    onPressed: () {
                      _handleGetContact();
                    },
                    child: const Text('REFRESH'),
                  ),
                  TextButton(
                    onPressed: _handleGetEmail,
                    child: const Text('ADD GMAIL SCOPE'),
                  ),
                ],
              )
            ],
          );
        },
      ),
    );
  }
}
