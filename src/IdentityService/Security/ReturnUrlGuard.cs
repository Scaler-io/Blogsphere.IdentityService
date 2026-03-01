using System;
using System.Linq;

namespace IdentityService.Security;

public static class ReturnUrlGuard
{
    private const string FallbackClientUrl = "http://localhost:4200";

    public static string NormalizeForClientApp(string returnUrl, string clientId = null)
    {
        if (IsAllowed(returnUrl, clientId))
        {
            return returnUrl;
        }

        return GetDefaultClientUrl(clientId);
    }

    public static string NormalizeForIdentityFlow(string returnUrl)
    {
        return IsAllowed(returnUrl) ? returnUrl : "/";
    }

    private static bool IsAllowed(string returnUrl, string clientId = null)
    {
        if (string.IsNullOrWhiteSpace(returnUrl))
        {
            return false;
        }

        if (IsLocalRelativeUrl(returnUrl))
        {
            return true;
        }

        if (!Uri.TryCreate(returnUrl, UriKind.Absolute, out var requestedUri))
        {
            return false;
        }

        var clientPool = string.IsNullOrWhiteSpace(clientId)
            ? Config.Clients
            : Config.Clients.Where(c => string.Equals(c.ClientId, clientId, StringComparison.OrdinalIgnoreCase));

        var allowedAbsoluteUrls = clientPool
            .SelectMany(c => c.RedirectUris.Concat(c.PostLogoutRedirectUris))
            .Where(u => !string.IsNullOrWhiteSpace(u))
            .Distinct(StringComparer.OrdinalIgnoreCase);

        return allowedAbsoluteUrls.Any(allowed =>
            Uri.TryCreate(allowed, UriKind.Absolute, out var allowedUri)
            && Uri.Compare(requestedUri, allowedUri, UriComponents.AbsoluteUri, UriFormat.SafeUnescaped, StringComparison.OrdinalIgnoreCase) == 0);
    }

    private static bool IsLocalRelativeUrl(string returnUrl)
    {
        return returnUrl.StartsWith("/", StringComparison.Ordinal)
               && !returnUrl.StartsWith("//", StringComparison.Ordinal)
               && !returnUrl.StartsWith("/\\", StringComparison.Ordinal);
    }

    private static string GetDefaultClientUrl(string clientId = null)
    {
        if (!string.IsNullOrWhiteSpace(clientId))
        {
            var clientMatch = Config.Clients.FirstOrDefault(c =>
                string.Equals(c.ClientId, clientId, StringComparison.OrdinalIgnoreCase));

            var clientUrl = clientMatch?.RedirectUris?.FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(clientUrl))
            {
                return clientUrl;
            }
        }

        var firstClientUrl = Config.Clients
            .SelectMany(c => c.RedirectUris)
            .FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(firstClientUrl))
        {
            return firstClientUrl;
        }

        return Config.Clients
            .FirstOrDefault(c => c.ClientId == "blogsphere-management")
            ?.RedirectUris
            ?.FirstOrDefault()
            ?? FallbackClientUrl;
    }
}
