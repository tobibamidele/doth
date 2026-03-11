// The single import point for doth consumers.
//
// Usage:
//   import 'package:doth/doth.dart';
//
// For shelf integration also import:
//   import 'package:doth/shelf_adapter.dart';

library;

/// doth — a multi-provider OAuth2 library for Dart backends.
/// Inspired by markbates/goth for Go.

// Core
export 'src/core/exceptions.dart';
export 'src/core/pkce.dart'
    show generateState, generateNonce, timingSafeEqual, PkceChallenge;
export 'src/core/provider.dart';
export 'src/core/registry.dart';
export 'src/core/session.dart';
export 'src/core/state_store.dart';
export 'src/core/token.dart';
export 'src/core/user.dart';

// Built-in providers
export 'src/providers/apple/apple_provider.dart';
export 'src/providers/discord/discord_provider.dart';
export 'src/providers/github/github_provider.dart';
export 'src/providers/google/google_provider.dart';
export 'src/providers/meta/meta_provider.dart';
export 'src/providers/microsoft/microsoft_provider.dart';
