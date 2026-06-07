using Microsoft.Extensions.Caching.Memory;

namespace IdentityService.Services.Account;

public class TwoFactorPendingState
{
    public string SessionId { get; set; }

    public string Email { get; set; }

    public string UserType { get; set; }

    public string ReturnUrl { get; set; }

    public bool RememberMe { get; set; }
}

public interface ITwoFactorPendingStore
{
    string Create(TwoFactorPendingState state);

    TwoFactorPendingState Get(string sessionId);

    void Refresh(string sessionId);

    void Remove(string sessionId);
}

public class TwoFactorPendingStore(IMemoryCache cache) : ITwoFactorPendingStore
{
    private const string CacheKeyPrefix = "2fa-pending:";
    private static readonly TimeSpan Expiry = TimeSpan.FromMinutes(10);

    public string Create(TwoFactorPendingState state)
    {
        var sessionId = Guid.NewGuid().ToString("N");
        state.SessionId = sessionId;
        cache.Set(GetCacheKey(sessionId), state, Expiry);
        return sessionId;
    }

    public TwoFactorPendingState Get(string sessionId)
    {
        if (string.IsNullOrWhiteSpace(sessionId))
        {
            return null;
        }

        return cache.TryGetValue(GetCacheKey(sessionId), out TwoFactorPendingState state)
            ? state
            : null;
    }

    public void Refresh(string sessionId)
    {
        var state = Get(sessionId);
        if (state != null)
        {
            cache.Set(GetCacheKey(sessionId), state, Expiry);
        }
    }

    public void Remove(string sessionId)
    {
        cache.Remove(GetCacheKey(sessionId));
    }

    private static string GetCacheKey(string sessionId) => $"{CacheKeyPrefix}{sessionId}";
}
