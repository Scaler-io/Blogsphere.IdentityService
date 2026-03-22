using System.Security.Claims;
using System.Security.Cryptography;
using Contracts.Events;
using IdentityService.Entities;
using IdentityService.Extensions;
using IdentityService.Management.Entities;
using IdentityService.Management.Models;
using IdentityService.Management.Services;
using IdentityService.Security;
using IdentityService.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdentityService.Pages.Account.Manage.TwoFactor;

[SecurityHeaders]
[Authorize]
[ValidateAntiForgeryToken]
public class Index(
    ILogger logger,
    UserManager<ApplicationUser> userManager,
    UserManager<ManagementUser> managementUserManager,
    IMultiUserStoreService multiUserStoreService,
    IPublishService publishService) : PageModel
{
    private const string OtpLoginProvider = "ManageAccount";
    private const string OtpCodeName = "Manage2FACode";
    private const string OtpCodeExpiryName = "Manage2FACodeExpiry";
    private const int OtpExpiryMinutes = 5;

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public bool TwoFactorEnabled { get; set; }
    public bool DisableCodeSent { get; set; }

    [TempData]
    public string StatusMessage { get; set; } = string.Empty;

    public async Task<IActionResult> OnGet([FromQuery] string returnUrl = null, [FromQuery] string clientId = null)
    {
        var safeReturnUrl = ReturnUrlGuard.NormalizeForClientApp(returnUrl, clientId);
        var email = GetCurrentUserEmail();
        if (string.IsNullOrWhiteSpace(email))
        {
            return RedirectToPage("/Account/Login/Index", new { returnUrl = safeReturnUrl });
        }

        Input = new InputModel
        {
            ReturnUrl = safeReturnUrl,
            ClientId = clientId ?? string.Empty
        };

        await LoadTwoFactorStatusAsync(email);
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        Input.ReturnUrl = ReturnUrlGuard.NormalizeForClientApp(Input.ReturnUrl, Input.ClientId);
        var email = GetCurrentUserEmail();
        if (string.IsNullOrWhiteSpace(email))
        {
            return RedirectToPage("/Account/Login/Index", new { returnUrl = Input.ReturnUrl });
        }

        var userStore = await multiUserStoreService.DetermineUserStoreByEmailAsync(email);

        switch (Input.Action)
        {
            case "enable":
                return await HandleEnableAsync(email, userStore);

            case "requestDisableCode":
                return await HandleRequestDisableCodeAsync(email, userStore);

            case "confirmDisable":
                return await HandleConfirmDisableAsync(email, userStore);

            default:
                await LoadTwoFactorStatusAsync(email);
                return Page();
        }
    }

    private async Task<IActionResult> HandleEnableAsync(string email, string userStore)
    {
        if (userStore == ManagementConstants.ManagementUserStore)
        {
            var user = await managementUserManager.FindByEmailAsync(email);
            if (user == null || !user.IsActive) return InvalidUserResult();

            await managementUserManager.SetTwoFactorEnabledAsync(user, true);
        }
        else
        {
            var user = await userManager.FindByEmailAsync(email);
            if (user == null || !user.IsActive) return InvalidUserResult();

            await userManager.SetTwoFactorEnabledAsync(user, true);
        }

        logger.Here().Information("2FA enabled for {UserType} user {Email}", userStore, email);
        StatusMessage = "Two-factor authentication has been enabled.";
        return Redirect(AppendQueryParam(Input.ReturnUrl, "twoFactor", "enabled"));
    }

    private async Task<IActionResult> HandleRequestDisableCodeAsync(string email, string userStore)
    {
        var code = RandomNumberGenerator.GetInt32(100000, 1000000).ToString("D6");

        if (userStore == ManagementConstants.ManagementUserStore)
        {
            var user = await managementUserManager.FindByEmailAsync(email);
            if (user == null || !user.IsActive) return InvalidUserResult();

            await managementUserManager.SetAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeName, code);
            await managementUserManager.SetAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeExpiryName,
                DateTime.UtcNow.AddMinutes(OtpExpiryMinutes).ToString("O"));
        }
        else
        {
            var user = await userManager.FindByEmailAsync(email);
            if (user == null || !user.IsActive) return InvalidUserResult();

            await userManager.SetAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeName, code);
            await userManager.SetAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeExpiryName,
                DateTime.UtcNow.AddMinutes(OtpExpiryMinutes).ToString("O"));
        }

        await publishService.PublishAsync(new AuthCodeSent
        {
            Email = email,
            Code = code
        }, Guid.NewGuid().ToString(), new
        {
            Purpose = "Disable2FA",
            UserType = userStore == ManagementConstants.ManagementUserStore ? "management" : "blogsphere"
        });

        logger.Here().Information("2FA disable verification code sent to {UserType} user {Email}", userStore, email);
        StatusMessage = "A verification code has been sent to your email.";
        TwoFactorEnabled = true;
        DisableCodeSent = true;
        return Page();
    }

    private async Task<IActionResult> HandleConfirmDisableAsync(string email, string userStore)
    {
        if (string.IsNullOrWhiteSpace(Input.VerificationCode))
        {
            ModelState.AddModelError("Input.VerificationCode", "Verification code is required.");
            TwoFactorEnabled = true;
            DisableCodeSent = true;
            return Page();
        }

        var (isValid, reason) = await ValidateOtpAsync(email, userStore, Input.VerificationCode);
        if (!isValid)
        {
            ModelState.AddModelError("Input.VerificationCode", reason);
            TwoFactorEnabled = true;
            DisableCodeSent = true;
            return Page();
        }

        if (userStore == ManagementConstants.ManagementUserStore)
        {
            var user = await managementUserManager.FindByEmailAsync(email);
            if (user == null || !user.IsActive) return InvalidUserResult();

            await managementUserManager.SetTwoFactorEnabledAsync(user, false);
            await managementUserManager.RemoveAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeName);
            await managementUserManager.RemoveAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeExpiryName);
        }
        else
        {
            var user = await userManager.FindByEmailAsync(email);
            if (user == null || !user.IsActive) return InvalidUserResult();

            await userManager.SetTwoFactorEnabledAsync(user, false);
            await userManager.RemoveAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeName);
            await userManager.RemoveAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeExpiryName);
        }

        logger.Here().Information("2FA disabled for {UserType} user {Email}", userStore, email);
        StatusMessage = "Two-factor authentication has been disabled.";
        return Redirect(AppendQueryParam(Input.ReturnUrl, "twoFactor", "disabled"));
    }

    private async Task<(bool isValid, string reason)> ValidateOtpAsync(string email, string userStore, string otpCode)
    {
        string savedCode;
        string expiryRaw;

        if (userStore == ManagementConstants.ManagementUserStore)
        {
            var user = await managementUserManager.FindByEmailAsync(email);
            if (user == null) return (false, "Invalid user.");
            savedCode = await managementUserManager.GetAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeName) ?? string.Empty;
            expiryRaw = await managementUserManager.GetAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeExpiryName) ?? string.Empty;
        }
        else
        {
            var user = await userManager.FindByEmailAsync(email);
            if (user == null) return (false, "Invalid user.");
            savedCode = await userManager.GetAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeName) ?? string.Empty;
            expiryRaw = await userManager.GetAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeExpiryName) ?? string.Empty;
        }

        if (string.IsNullOrWhiteSpace(savedCode) || string.IsNullOrWhiteSpace(expiryRaw))
            return (false, "No active verification code. Please request a new code.");

        if (!DateTime.TryParse(expiryRaw, out var expiryUtc) || DateTime.UtcNow > expiryUtc)
            return (false, "Verification code expired. Please request a new code.");

        if (!string.Equals(savedCode, otpCode, StringComparison.Ordinal))
            return (false, "Invalid verification code.");

        return (true, string.Empty);
    }

    private async Task LoadTwoFactorStatusAsync(string email)
    {
        var userStore = await multiUserStoreService.DetermineUserStoreByEmailAsync(email);

        if (userStore == ManagementConstants.ManagementUserStore)
        {
            var user = await managementUserManager.FindByEmailAsync(email);
            TwoFactorEnabled = user != null && await managementUserManager.GetTwoFactorEnabledAsync(user);
        }
        else
        {
            var user = await userManager.FindByEmailAsync(email);
            TwoFactorEnabled = user != null && await userManager.GetTwoFactorEnabledAsync(user);
        }
    }

    private string GetCurrentUserEmail()
    {
        return User.FindFirstValue(ClaimTypes.Email)
            ?? User.FindFirstValue("email")
            ?? User.Identity?.Name
            ?? string.Empty;
    }

    private IActionResult InvalidUserResult()
    {
        ModelState.AddModelError(string.Empty, "Unable to process request. Account may be inactive.");
        return Page();
    }

    private static string AppendQueryParam(string url, string key, string value)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return url;
        }

        var separator = url.Contains('?') ? "&" : "?";
        return $"{url}{separator}{Uri.EscapeDataString(key)}={Uri.EscapeDataString(value ?? string.Empty)}";
    }
}
