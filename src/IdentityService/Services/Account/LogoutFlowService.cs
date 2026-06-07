using System.Security.Claims;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Services;
using IdentityModel;
using IdentityService.Entities;
using IdentityService.Models.Api.Account;
using IdentityService.Pages.Logout;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Telemetry = IdentityService.Pages.Telemetry;

namespace IdentityService.Services.Account;

public class LogoutFlowService(
    SignInManager<ApplicationUser> signInManager,
    IIdentityServerInteractionService interaction,
    IEventService events,
    IHttpContextAccessor httpContextAccessor) : ILogoutFlowService
{
    public async Task<LogoutContextResponse> GetLogoutContextAsync(string logoutId, ClaimsPrincipal user)
    {
        var isAuthenticated = user.Identity?.IsAuthenticated == true;
        var showLogoutPrompt = LogoutOptions.ShowLogoutPrompt;

        if (!isAuthenticated)
        {
            showLogoutPrompt = false;
        }
        else
        {
            var context = await interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                showLogoutPrompt = false;
            }
        }

        return new LogoutContextResponse
        {
            ShowLogoutPrompt = showLogoutPrompt,
            LogoutId = logoutId,
            IsAuthenticated = isAuthenticated
        };
    }

    public async Task<LogoutResponse> LogoutAsync(LogoutRequest request, ClaimsPrincipal user, Func<string, string> buildLoggedOutUrl)
    {
        if (user.Identity?.IsAuthenticated != true)
        {
            return new LogoutResponse
            {
                Outcome = LogoutOutcome.NotAuthenticated,
                RedirectUrl = buildLoggedOutUrl(request.LogoutId)
            };
        }

        var logoutId = request.LogoutId;
        if (string.IsNullOrEmpty(logoutId))
        {
            logoutId = await interaction.CreateLogoutContextAsync();
        }

        await signInManager.SignOutAsync();

        var idp = user.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
        await events.RaiseAsync(new UserLogoutSuccessEvent(user.GetSubjectId(), user.GetDisplayName()));
        Telemetry.Metrics.UserLogout(idp);

        if (idp != null && idp != Duende.IdentityServer.IdentityServerConstants.LocalIdentityProvider)
        {
            var httpContext = httpContextAccessor.HttpContext;
            if (httpContext != null && await httpContext.GetSchemeSupportsSignOutAsync(idp))
            {
                return new LogoutResponse
                {
                    Outcome = LogoutOutcome.FederatedSignOutRequired,
                    LogoutId = logoutId,
                    FederatedSignOutScheme = idp,
                    RedirectUrl = buildLoggedOutUrl(logoutId)
                };
            }
        }

        return new LogoutResponse
        {
            Outcome = LogoutOutcome.Success,
            LogoutId = logoutId,
            RedirectUrl = buildLoggedOutUrl(logoutId)
        };
    }
}

internal static class LogoutHttpContextExtensions
{
    public static async Task<bool> GetSchemeSupportsSignOutAsync(this HttpContext context, string scheme)
    {
        var provider = context.RequestServices.GetRequiredService<IAuthenticationHandlerProvider>();
        var handler = await provider.GetHandlerAsync(context, scheme);
        return handler is IAuthenticationSignOutHandler;
    }
}
