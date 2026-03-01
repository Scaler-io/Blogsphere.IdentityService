// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdentityService.Pages.Ciba;

[AllowAnonymous]
[SecurityHeaders]
[ValidateAntiForgeryToken]
public class IndexModel(IBackchannelAuthenticationInteractionService backchannelAuthenticationInteractionService, ILogger<IndexModel> logger) : PageModel
{
    public BackchannelUserLoginRequest LoginRequest { get; set; } = default!;

    private readonly IBackchannelAuthenticationInteractionService _backchannelAuthenticationInteraction = backchannelAuthenticationInteractionService;
    private readonly ILogger<IndexModel> _logger = logger;

    public async Task<IActionResult> OnGet(string id)
    {
        var result = await _backchannelAuthenticationInteraction.GetLoginRequestByInternalIdAsync(id);
        if (result == null)
        {
            return RedirectToPage("/Home/Error/Index");
        }
        else
        {
            LoginRequest = result;
        }

        return Page();
    }
}