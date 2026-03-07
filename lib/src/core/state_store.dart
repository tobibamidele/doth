/*
 * StateStore (abstract interface)
 * Pluggable storage for OAuth state & PKCE verifiers between the
 * authorization redirect and the callback. The default is [InMemoryStateStore].
 * In production, replace with a Redis- or DB-backed implementation.
 *
 * Example (custom Redis store):
 *   class RedisStateStore implements StateStore {
 *     @override
 *     Future<void> save(String state, {Duration? ttl, Map<String,String>? extra}) =>
 *         redis.setEx(state, ttl?.inSeconds ?? 600, jsonEncode(extra));
 *     // ...
 *   }
 *   DartGoth.stateStore = RedisStateStore();
 */

/// Data stored alongside a state key during an OAuth flow.
class StateEntry {
  /// The PKCE code verifier (if PKCE is enabled for this flow).
  final String? pkceVerifier;

  /// The provider name for which the state was generated.
  final String providerName;

  /// Any extra key/value pairs the caller wants to round-trip through the flow.
  final Map<String, String> extra;

  /// When this entry must be considered invalid.
  final DateTime expiry;

  const StateEntry({
    required this.providerName,
    required this.expiry,
    this.pkceVerifier,
    this.extra = const {},
  });
}

/// Contract for storing and retrieving OAuth state between redirects.
abstract interface class StateStore {
  /*
   * save
   * Persists a state entry under the given [state] key.
   * The entry MUST expire after [ttl] (default: 10 minutes).
   *
   * Example:
   *   await stateStore.save('abc123', StateEntry(providerName: 'github', expiry: ...));
   */
  Future<void> save(String state, StateEntry entry);

  /*
   * consume
   * Retrieves AND removes the entry for [state].
   * Returns `null` if the state is unknown or has expired.
   * "Consume" semantics prevent replay of the same state.
   *
   * Example:
   *   final entry = await stateStore.consume(callbackState);
   *   if (entry == null) throw OAuthException('Invalid or expired state');
   */
  Future<StateEntry?> consume(String state);

  /*
   * purgeExpired
   * Removes all entries past their expiry time.
   * Call this periodically to avoid unbounded memory growth.
   *
   * Example:
   *   Timer.periodic(Duration(minutes: 5), (_) => stateStore.purgeExpired());
   */
  Future<void> purgeExpired();
}

/// Default in-memory state store.
///
/// WARNING: Not suitable for multi-instance deployments — each server process
/// has its own map. Use a distributed store (Redis, Memcached, DB) instead.
class InMemoryStateStore implements StateStore {
  final _store = <String, StateEntry>{};

  /// Default TTL for state entries.
  final Duration defaultTtl;

  InMemoryStateStore({this.defaultTtl = const Duration(minutes: 10)});

  @override
  Future<void> save(String state, StateEntry entry) async {
    _store[state] = entry;
  }

  @override
  Future<StateEntry?> consume(String state) async {
    final entry = _store.remove(state);
    if (entry == null) return null;
    if (DateTime.now().isAfter(entry.expiry)) return null;
    return entry;
  }

  @override
  Future<void> purgeExpired() async {
    final now = DateTime.now();
    _store.removeWhere((_, entry) => now.isAfter(entry.expiry));
  }
}
