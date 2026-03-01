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

namespace IdentityService.Pages.Account.SelfResetPassword.VerifyCode;

[SecurityHeaders]
[Authorize]
[ValidateAntiForgeryToken]
public class Index(
    UserManager<ApplicationUser> userManager,
    UserManager<ManagementUser> managementUserManager,
    IMultiUserStoreService multiUserStoreService,
    IPublishService publishService) : PageModel
{
    private const string OtpLoginProvider = "SelfResetPassword";
    private const string OtpCodeName = "OtpCode";
    private const string OtpCodeExpiryName = "OtpCodeExpiry";
    private const string OtpVerifiedName = "OtpVerified";
    private const int OtpExpiryMinutes = 10;

    private readonly UserManager<ApplicationUser> _userManager = userManager;
    private readonly UserManager<ManagementUser> _managementUserManager = managementUserManager;
    private readonly IMultiUserStoreService _multiUserStoreService = multiUserStoreService;
    private readonly IPublishService _publishService = publishService;

    [BindProperty]
    public InputModel Input { get; set; } = new();

    [TempData]
    public string StatusMessage { get; set; } = string.Empty;

    public IActionResult OnGet([FromQuery] string returnUrl = null, [FromQuery] string clientId = null)
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
            ClientId = clientId ?? string.Empty
        };

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

        if (Input.Action == "sendCode")
        {
            var oneTimeCode = RandomNumberGenerator.GetInt32(100000, 1000000).ToString("D6");
            await SaveOtpAsync(currentEmail, userStore, oneTimeCode, DateTime.UtcNow.AddMinutes(OtpExpiryMinutes), isVerified: false);

            await _publishService.PublishAsync<PasswordResetOneTimeCodeSent>(new()
            {
                Email = currentEmail,
                Code = oneTimeCode
            }, Guid.NewGuid().ToString(), new
            {
                UserType = userStore == ManagementConstants.ManagementUserStore ? "management" : "blogsphere",
                ReturnUrl = Input.ReturnUrl,
                ClientId = Input.ClientId
            });

            StatusMessage = "One-time code sent to your email.";
            return RedirectToPage(new { returnUrl = Input.ReturnUrl, clientId = Input.ClientId });
        }

        if (Input.Action == "verifyCode")
        {
            if (string.IsNullOrWhiteSpace(Input.OneTimeCode))
            {
                ModelState.AddModelError("Input.OneTimeCode", "One-time code is required.");
                return Page();
            }

            var (isValid, reason) = await ValidateOtpAsync(currentEmail, userStore, Input.OneTimeCode);
            if (!isValid)
            {
                ModelState.AddModelError("Input.OneTimeCode", reason);
                return Page();
            }

            await SetOtpVerifiedAsync(currentEmail, userStore, isVerified: true);
            return RedirectToPage("/Account/SelfResetPassword/ChangePassword/Index", new
            {
                mode = "code",
                returnUrl = Input.ReturnUrl,
                clientId = Input.ClientId
            });
        }

        return Page();
    }

    private string GetCurrentUserEmail()
    {
        return User.FindFirstValue(ClaimTypes.Email)
            ?? User.FindFirstValue("email")
            ?? User.Identity?.Name
            ?? string.Empty;
    }

    private async Task SaveOtpAsync(string email, string userStore, string code, DateTime expiryUtc, bool isVerified)
    {
        if (userStore == ManagementConstants.ManagementUserStore)
        {
            var user = await _managementUserManager.FindByEmailAsync(email);
            if (user == null) return;

            await _managementUserManager.SetAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeName, code);
            await _managementUserManager.SetAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeExpiryName, expiryUtc.ToString("O"));
            await _managementUserManager.SetAuthenticationTokenAsync(user, OtpLoginProvider, OtpVerifiedName, isVerified.ToString());
            return;
        }

        var appUser = await _userManager.FindByEmailAsync(email);
        if (appUser == null) return;

        await _userManager.SetAuthenticationTokenAsync(appUser, OtpLoginProvider, OtpCodeName, code);
        await _userManager.SetAuthenticationTokenAsync(appUser, OtpLoginProvider, OtpCodeExpiryName, expiryUtc.ToString("O"));
        await _userManager.SetAuthenticationTokenAsync(appUser, OtpLoginProvider, OtpVerifiedName, isVerified.ToString());
    }

    private async Task<(bool isValid, string reason)> ValidateOtpAsync(string email, string userStore, string otpCode)
    {
        string savedCode;
        string expiryRaw;

        if (userStore == ManagementConstants.ManagementUserStore)
        {
            var user = await _managementUserManager.FindByEmailAsync(email);
            if (user == null) return (false, "Invalid user.");
            savedCode = await _managementUserManager.GetAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeName) ?? string.Empty;
            expiryRaw = await _managementUserManager.GetAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeExpiryName) ?? string.Empty;
        }
        else
        {
            var appUser = await _userManager.FindByEmailAsync(email);
            if (appUser == null) return (false, "Invalid user.");
            savedCode = await _userManager.GetAuthenticationTokenAsync(appUser, OtpLoginProvider, OtpCodeName) ?? string.Empty;
            expiryRaw = await _userManager.GetAuthenticationTokenAsync(appUser, OtpLoginProvider, OtpCodeExpiryName) ?? string.Empty;
        }

        return ValidateOtpToken(savedCode, expiryRaw, otpCode);
    }

    private static (bool isValid, string reason) ValidateOtpToken(string savedCode, string expiryRaw, string otpCode)
    {
        if (string.IsNullOrWhiteSpace(savedCode) || string.IsNullOrWhiteSpace(expiryRaw))
            return (false, "No active one-time code. Please request a new code.");

        if (!DateTime.TryParse(expiryRaw, out var expiryUtc) || DateTime.UtcNow > expiryUtc)
            return (false, "One-time code expired. Please request a new code.");

        if (!string.Equals(savedCode, otpCode, StringComparison.Ordinal))
            return (false, "Invalid one-time code.");

        return (true, string.Empty);
    }

    private async Task SetOtpVerifiedAsync(string email, string userStore, bool isVerified)
    {
        if (userStore == ManagementConstants.ManagementUserStore)
        {
            var user = await _managementUserManager.FindByEmailAsync(email);
            if (user == null) return;
            await _managementUserManager.SetAuthenticationTokenAsync(user, OtpLoginProvider, OtpVerifiedName, isVerified.ToString());
            return;
        }

        var appUser = await _userManager.FindByEmailAsync(email);
        if (appUser == null) return;
        await _userManager.SetAuthenticationTokenAsync(appUser, OtpLoginProvider, OtpVerifiedName, isVerified.ToString());
    }
}
