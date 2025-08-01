// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using Duende.IdentityServer.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdentityService.Pages.Logout;

[SecurityHeaders]
[AllowAnonymous]
public class LoggedOut(IIdentityServerInteractionService interactionService) : PageModel
{
    private readonly IIdentityServerInteractionService _interactionService = interactionService;

    public LoggedOutViewModel View { get; set; } = default!;

    public async Task OnGet(string logoutId)
    {
        // get context information (client name, post logout redirect URI and iframe for federated signout)
        var logout = await _interactionService.GetLogoutContextAsync(logoutId);

        View = new LoggedOutViewModel
        {
            AutomaticRedirectAfterSignOut = LogoutOptions.AutomaticRedirectAfterSignOut,
            PostLogoutRedirectUri = logout?.PostLogoutRedirectUri ?? "/Account/Login",
            ClientName = String.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId ?? "" : logout?.ClientName ?? "",
            SignOutIframeUrl = logout?.SignOutIFrameUrl ?? ""
        };
    }
}
