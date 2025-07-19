using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Services;
using IdentityService.Entities;
using IdentityService.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Authorization;
using IdentityService.Management.Entities;
using IdentityService.Management.Models;

namespace IdentityService.Pages.Account.TwoFactor;

[SecurityHeaders]
[AllowAnonymous]
public class Index(
    ILogger logger,
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager,
    UserManager<ManagementUser> managementUserManager,
    SignInManager<ManagementUser> managementSignInManager,
    IEventService events,
    IIdentityServerInteractionService interaction) : PageModel
{
    private readonly ILogger _logger = logger;
    private readonly IEventService _events = events;
    private readonly IIdentityServerInteractionService _interaction = interaction;
    private readonly UserManager<ApplicationUser> _userManager = userManager;
    private readonly SignInManager<ApplicationUser> _signInManager = signInManager;
    private readonly UserManager<ManagementUser> _managementUserManager = managementUserManager;
    private readonly SignInManager<ManagementUser> _managementSignInManager = managementSignInManager;

    [BindProperty] public string Code { get; set; } = default!;

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
        var userType = TempData["2FA_UserType"] as string ?? "blogsphere";

        var context = await _interaction.GetAuthorizationContextAsync(returnUrl);

        if(string.IsNullOrEmpty(Code))
        {
            ModelState.AddModelError("Code", "Code is required");
            SetTempData(userEmail, returnUrl, rememberMe, userType);
            return Page();
        }

        if (userType == "management")
        {
            // Handle management user 2FA
            var managementUser = await _managementUserManager.FindByEmailAsync(userEmail);
            if (managementUser == null)
            {
                ModelState.AddModelError(string.Empty, "Invalid user.");
                SetTempData(userEmail, returnUrl, rememberMe, userType);
                return Page();
            }

            var result = await _managementUserManager.VerifyTwoFactorTokenAsync(managementUser, ManagementConstants.ManagementTwoFactorTokenProvider, Code);
            if(!result)
            {
                ModelState.AddModelError("Code", "The code is invalid");
                Code = string.Empty;
                SetTempData(userEmail, returnUrl, rememberMe, userType);
                return Page();
            }

            await _managementSignInManager.SignInAsync(managementUser, rememberMe);
            await _managementUserManager.RemoveAuthenticationTokenAsync(managementUser, "2Fa", "2FACode");
            await _managementUserManager.RemoveAuthenticationTokenAsync(managementUser, "2Fa", "2FACodeExpiry");

            await _events.RaiseAsync(new UserLoginSuccessEvent(managementUser.UserName, managementUser.Id, managementUser.FullName, clientId: context?.Client.ClientId));
            Telemetry.Metrics.UserLogin(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider);

            managementUser.SetLastLogin();
            await _managementUserManager.UpdateAsync(managementUser);
        }
        else
        {
            // Handle blogsphere user 2FA (existing logic)
            var user = await _userManager.FindByEmailAsync(userEmail);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Invalid user.");
                SetTempData(userEmail, returnUrl, rememberMe, userType);
                return Page();
            }

            var result = await _userManager.VerifyTwoFactorTokenAsync(user, Constants.CustomTwoFactorTokenProvider, Code);
            if(!result)
            {
                ModelState.AddModelError("Code", "The code is invalid");
                Code = string.Empty;
                SetTempData(userEmail, returnUrl, rememberMe, userType);
                return Page();
            }

            await _signInManager.SignInAsync(user, rememberMe);
            await _userManager.RemoveAuthenticationTokenAsync(user, "2Fa", "2FACode");
            await _userManager.RemoveAuthenticationTokenAsync(user, "2Fa", "2FACodeExpiry");

            await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.FullName, clientId: context?.Client.ClientId));
            Telemetry.Metrics.UserLogin(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider);

            user.SetLastLogin();
            await _userManager.UpdateAsync(user);
        }

        return Redirect(returnUrl);
    }

    private void SetTempData(string userEmail, string returnUrl, bool rememberLogin, string userType = "blogsphere")
    {
        TempData["2FA_UserEmail"] = userEmail;
        TempData["2FA_ReturnUrl"] = returnUrl;
        TempData["2FA_RemberMe"] = rememberLogin;
        TempData["2FA_UserType"] = userType;
    }
}
