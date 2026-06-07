using IdentityService.Models.Api.Account;
using System.Security.Claims;

namespace IdentityService.Services.Account;

public interface ILogoutFlowService
{
    Task<LogoutContextResponse> GetLogoutContextAsync(string logoutId, ClaimsPrincipal user);

    Task<LogoutResponse> LogoutAsync(LogoutRequest request, ClaimsPrincipal user, Func<string, string> buildLoggedOutUrl);
}
