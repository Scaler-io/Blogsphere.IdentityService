using System.Security.Claims;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;
using IdentityService.Entities;
using IdentityService.Extensions;
using IdentityService.Management.Entities;
using IdentityService.Management.Models;
using IdentityService.Management.Services;
using IdentityService.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdentityService.Pages.Account.SelfResetPassword.ChangePassword;

[SecurityHeaders]
[Authorize]
[ValidateAntiForgeryToken]
public class Index(
    UserManager<ApplicationUser> userManager,
    UserManager<ManagementUser> managementUserManager,
    SignInManager<ApplicationUser> signInManager,
    SignInManager<ManagementUser> managementSignInManager,
    IMultiUserStoreService multiUserStoreService,
    IPersistedGrantStore persistedGrantStore,
    ILogger logger) : PageModel
{
    private const string OtpLoginProvider = "SelfResetPassword";
    private const string OtpCodeName = "OtpCode";
    private const string OtpCodeExpiryName = "OtpCodeExpiry";
    private const string OtpVerifiedName = "OtpVerified";

    private readonly UserManager<ApplicationUser> _userManager = userManager;
    private readonly UserManager<ManagementUser> _managementUserManager = managementUserManager;
    private readonly SignInManager<ApplicationUser> _signInManager = signInManager;
    private readonly SignInManager<ManagementUser> _managementSignInManager = managementSignInManager;
    private readonly IMultiUserStoreService _multiUserStoreService = multiUserStoreService;
    private readonly IPersistedGrantStore _persistedGrantStore = persistedGrantStore;
    private readonly ILogger _logger = logger;

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public bool IsCodeMode => string.Equals(Input.Mode, "code", StringComparison.OrdinalIgnoreCase);

    public async Task<IActionResult> OnGet([FromQuery] string mode = "current", [FromQuery] string returnUrl = null, [FromQuery] string clientId = null)
    {
        var safeReturnUrl = ReturnUrlGuard.NormalizeForClientApp(returnUrl, clientId);
        var currentEmail = GetCurrentUserEmail();
        if (string.IsNullOrWhiteSpace(currentEmail))
        {
            return RedirectToPage("/Account/Login/Index", new { returnUrl = safeReturnUrl });
        }

        Input = new InputModel
        {
            Email = currentEmail,
            ReturnUrl = safeReturnUrl,
            ClientId = clientId ?? string.Empty,
            Mode = mode
        };

        if (IsCodeMode)
        {
            var userStore = await _multiUserStoreService.DetermineUserStoreByEmailAsync(currentEmail);
            if (!await IsOtpVerifiedAsync(currentEmail, userStore))
            {
                return RedirectToPage("/Account/SelfResetPassword/VerifyCode/Index", new { returnUrl = Input.ReturnUrl, clientId = Input.ClientId });
            }
        }

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        Input.ReturnUrl = ReturnUrlGuard.NormalizeForClientApp(Input.ReturnUrl, Input.ClientId);
        var currentEmail = GetCurrentUserEmail();
        if (string.IsNullOrWhiteSpace(currentEmail))
        {
            return RedirectToPage("/Account/Login/Index", new { returnUrl = Input.ReturnUrl });
        }

        Input.Email = currentEmail;

        var userStore = await _multiUserStoreService.DetermineUserStoreByEmailAsync(currentEmail);
        var codeMode = string.Equals(Input.Mode, "code", StringComparison.OrdinalIgnoreCase);

        if (codeMode && !await IsOtpVerifiedAsync(currentEmail, userStore))
        {
            ModelState.AddModelError(string.Empty, "One-time code verification is required.");
            return Page();
        }

        if (!codeMode && string.IsNullOrWhiteSpace(Input.CurrentPassword))
        {
            ModelState.AddModelError("Input.CurrentPassword", "Current password is required.");
            return Page();
        }
        
        if (string.IsNullOrWhiteSpace(Input.NewPassword))
        {
            ModelState.AddModelError("Input.NewPassword", "New password is required.");
            return Page();
        }

        if (!string.Equals(Input.NewPassword, Input.ConfirmPassword, StringComparison.Ordinal))
        {
            ModelState.AddModelError("Input.ConfirmPassword", "The password and confirmation password do not match.");
            return Page();
        }

        if (userStore == ManagementConstants.ManagementUserStore)
        {
            var managementUser = await _managementUserManager.FindByEmailAsync(currentEmail);
            if (managementUser == null)
            {
                return RedirectToPage("/Account/Login/Index", new { returnUrl = Input.ReturnUrl });
            }

            IdentityResult result;
            if (codeMode)
            {
                await _managementUserManager.RemovePasswordAsync(managementUser);
                result = await _managementUserManager.AddPasswordAsync(managementUser, Input.NewPassword);
            }
            else
            {
                var isCurrentPasswordValid = await _managementUserManager.CheckPasswordAsync(managementUser, Input.CurrentPassword);
                if (!isCurrentPasswordValid)
                {
                    ModelState.AddModelError("Input.CurrentPassword", "Current password is incorrect.");
                    return Page();
                }

                result = await _managementUserManager.ChangePasswordAsync(managementUser, Input.CurrentPassword, Input.NewPassword);
            }

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    var isCurrentPasswordError = !codeMode
                        && (string.Equals(error.Code, "PasswordMismatch", StringComparison.OrdinalIgnoreCase)
                            || string.Equals(error.Code, "InvalidPassword", StringComparison.OrdinalIgnoreCase)
                            || error.Description.Contains("incorrect password", StringComparison.OrdinalIgnoreCase)
                            || error.Description.Contains("password mismatch", StringComparison.OrdinalIgnoreCase));

                    if (isCurrentPasswordError)
                    {
                        ModelState.AddModelError("Input.CurrentPassword", error.Description);
                    }
                    else
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                }

                return Page();
            }

            if (codeMode)
            {
                await ClearOtpAsync(currentEmail, userStore);
            }

            await RevokeTokensAndSignOutAsync(managementUser.Id, currentEmail);
            await _managementSignInManager.PasswordSignInAsync(managementUser, Input.NewPassword, isPersistent: true, lockoutOnFailure: false);
            return Redirect(AppendPasswordResetParam(Input.ReturnUrl));
        }

        var appUser = await _userManager.FindByEmailAsync(currentEmail);
        if (appUser == null)
        {
            return RedirectToPage("/Account/Login/Index", new { returnUrl = Input.ReturnUrl });
        }

        IdentityResult appResult;
        if (codeMode)
        {
            await _userManager.RemovePasswordAsync(appUser);
            appResult = await _userManager.AddPasswordAsync(appUser, Input.NewPassword);
        }
        else
        {
            var isCurrentPasswordValid = await _userManager.CheckPasswordAsync(appUser, Input.CurrentPassword);
            if (!isCurrentPasswordValid)
            {
                ModelState.AddModelError("Input.CurrentPassword", "Current password is incorrect.");
                return Page();
            }

            appResult = await _userManager.ChangePasswordAsync(appUser, Input.CurrentPassword, Input.NewPassword);
        }

        if (!appResult.Succeeded)
        {
            foreach (var error in appResult.Errors)
            {
                var isCurrentPasswordError = !codeMode
                    && (string.Equals(error.Code, "PasswordMismatch", StringComparison.OrdinalIgnoreCase)
                        || string.Equals(error.Code, "InvalidPassword", StringComparison.OrdinalIgnoreCase)
                        || error.Description.Contains("incorrect password", StringComparison.OrdinalIgnoreCase)
                        || error.Description.Contains("password mismatch", StringComparison.OrdinalIgnoreCase));

                if (isCurrentPasswordError)
                {
                    ModelState.AddModelError("Input.CurrentPassword", error.Description);
                }
                else
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            return Page();
        }

        if (codeMode)
        {
            await ClearOtpAsync(currentEmail, userStore);
        }

        await RevokeTokensAndSignOutAsync(appUser.Id, currentEmail);
        await _signInManager.PasswordSignInAsync(appUser, Input.NewPassword, isPersistent: true, lockoutOnFailure: false);
        return Redirect(AppendPasswordResetParam(Input.ReturnUrl));
    }

    private static string AppendPasswordResetParam(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return url;
        var separator = url.Contains('?') ? "&" : "?";
        return url + separator + "passwordReset=success";
    }

    private string GetCurrentUserEmail()
    {
        return User.FindFirstValue(ClaimTypes.Email)
            ?? User.FindFirstValue("email")
            ?? User.Identity?.Name
            ?? string.Empty;
    }

    private async Task<bool> IsOtpVerifiedAsync(string email, string userStore)
    {
        if (userStore == ManagementConstants.ManagementUserStore)
        {
            var user = await _managementUserManager.FindByEmailAsync(email);
            if (user == null) return false;

            var isVerifiedRaw = await _managementUserManager.GetAuthenticationTokenAsync(user, OtpLoginProvider, OtpVerifiedName);
            return bool.TryParse(isVerifiedRaw, out var isVerified) && isVerified;
        }

        var appUser = await _userManager.FindByEmailAsync(email);
        if (appUser == null) return false;
        var appVerifiedRaw = await _userManager.GetAuthenticationTokenAsync(appUser, OtpLoginProvider, OtpVerifiedName);
        return bool.TryParse(appVerifiedRaw, out var appVerified) && appVerified;
    }

    private async Task ClearOtpAsync(string email, string userStore)
    {
        if (userStore == ManagementConstants.ManagementUserStore)
        {
            var user = await _managementUserManager.FindByEmailAsync(email);
            if (user == null) return;

            await _managementUserManager.RemoveAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeName);
            await _managementUserManager.RemoveAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeExpiryName);
            await _managementUserManager.RemoveAuthenticationTokenAsync(user, OtpLoginProvider, OtpVerifiedName);
            return;
        }

        var appUser = await _userManager.FindByEmailAsync(email);
        if (appUser == null) return;

        await _userManager.RemoveAuthenticationTokenAsync(appUser, OtpLoginProvider, OtpCodeName);
        await _userManager.RemoveAuthenticationTokenAsync(appUser, OtpLoginProvider, OtpCodeExpiryName);
        await _userManager.RemoveAuthenticationTokenAsync(appUser, OtpLoginProvider, OtpVerifiedName);
    }

    private async Task RevokeTokensAndSignOutAsync(string subjectId, string email)
    {
        await _persistedGrantStore.RemoveAllAsync(new PersistedGrantFilter
        {
            SubjectId = subjectId
        });
        _logger.Here().Information("Revoked persisted grants after password reset for {Email}", email);
    }
}
