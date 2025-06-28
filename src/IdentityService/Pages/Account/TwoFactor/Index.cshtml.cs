using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Services;
using IdentityService.Entities;
using IdentityService.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Authorization;

namespace IdentityService.Pages.Account.TwoFactor;

[SecurityHeaders]
[AllowAnonymous]
public class Index : PageModel
{
    private readonly ILogger _logger;
    private readonly IEventService _events;
    private readonly IIdentityServerInteractionService _interaction;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;

    [BindProperty] public string Code { get; set; } = default!;
    public Index(ILogger logger, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IEventService events, IIdentityServerInteractionService interaction)
    {
        _logger = logger;
        _userManager = userManager;
        _signInManager = signInManager;
        _events = events;
        _interaction = interaction;
    }

    public IActionResult OnGet()
    {
        var userEmail = TempData.Peek("2FA_UserEmail") as string;
        if (string.IsNullOrEmpty(userEmail))
        {
            return RedirectToPage("/Account/Login/Index");
        }

        return Page();
    }

    public async Task<IActionResult> OnPost()
    {
        var userEmail = TempData["2FA_UserEmail"] as string;
        var rememberMe = TempData["2FA_RemberMe"] as bool? ?? false;
        var returnUrl = TempData["2FA_ReturnUrl"] as string ?? "~/";

        var context = await _interaction.GetAuthorizationContextAsync(returnUrl);

        if(string.IsNullOrEmpty(Code))
        {
            ModelState.AddModelError("Code", "Code is required");
            SetTempData(userEmail, returnUrl, rememberMe);
            return Page();
        }

        var user = await _userManager.FindByEmailAsync(userEmail);
        if (user == null)
        {
            ModelState.AddModelError(string.Empty, "Invalid user.");
            SetTempData(userEmail, returnUrl, rememberMe);
            return Page();
        }

        var result = await _userManager.VerifyTwoFactorTokenAsync(user, Constants.CustomTwoFactorTokenProvider, Code);
        if(!result)
        {
            ModelState.AddModelError("Code", "The code is invalid");
            Code = string.Empty;
            SetTempData(userEmail, returnUrl, rememberMe);
            return Page();
        }

        await _signInManager.SignInAsync(user, rememberMe);
        await _userManager.RemoveAuthenticationTokenAsync(user, "2Fa", "2FACode");
        await _userManager.RemoveAuthenticationTokenAsync(user, "2Fa", "2FACodeExpiry");

        await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName, clientId: context?.Client.ClientId));
        Telemetry.Metrics.UserLogin(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider);

        return Redirect(returnUrl);
    }

    private void SetTempData(string userEmail, string returnUrl, bool rememberLogin)
    {
        TempData["2FA_UserEmail"] = userEmail;
        TempData["2FA_ReturnUrl"] = returnUrl;
        TempData["2FA_RemberMe"] = rememberLogin;
    }
}
