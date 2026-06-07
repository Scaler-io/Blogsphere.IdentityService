using Duende.IdentityServer.Models;

namespace IdentityService.Services.Account;

internal static class IdentityFlowHelpers
{
    public static bool IsNativeClient(AuthorizationRequest context)
    {
        if (context?.RedirectUri == null)
        {
            return false;
        }

        return !context.RedirectUri.StartsWith("https", StringComparison.Ordinal)
               && !context.RedirectUri.StartsWith("http", StringComparison.Ordinal);
    }
}
