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

namespace IdentityService.Pages.Account.Manage.Phone.VerifyCode;

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
    private const string OtpCodeName = "PhoneVerifyCode";
    private const string OtpCodeExpiryName = "PhoneVerifyCodeExpiry";
    private const int OtpExpiryMinutes = 10;

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string MaskedPhone { get; set; } = string.Empty;

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

        var hasPhone = await HasPhoneNumberAsync(email);
        if (!hasPhone)
        {
            return RedirectToPage("/Account/Manage/Phone/Index", new { returnUrl = safeReturnUrl, clientId });
        }

        Input = new InputModel
        {
            ReturnUrl = safeReturnUrl,
            ClientId = clientId ?? string.Empty
        };

        await LoadMaskedPhoneAsync(email);
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
        await LoadMaskedPhoneAsync(email);

        switch (Input.Action)
        {
            case "sendCode":
                return await HandleSendCodeAsync(email, userStore);

            case "verifyCode":
                return await HandleVerifyCodeAsync(email, userStore);

            default:
                return Page();
        }
    }

    private async Task<IActionResult> HandleSendCodeAsync(string email, string userStore)
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

        await publishService.PublishAsync(new PhoneVerificationCodeSent
        {
            Email = email,
            Code = code
        }, Guid.NewGuid().ToString(), new
        {
            Purpose = "PhoneVerification",
            UserType = userStore == ManagementConstants.ManagementUserStore ? "management" : "blogsphere"
        });

        logger.Here().Information("Phone verification code sent to {UserType} user {Email}", userStore, email);
        StatusMessage = "A verification code has been sent to your email.";
        return RedirectToPage(new { returnUrl = Input.ReturnUrl, clientId = Input.ClientId });
    }

    private async Task<IActionResult> HandleVerifyCodeAsync(string email, string userStore)
    {
        if (string.IsNullOrWhiteSpace(Input.VerificationCode))
        {
            ModelState.AddModelError("Input.VerificationCode", "Verification code is required.");
            return Page();
        }

        var (isValid, reason) = await ValidateOtpAsync(email, userStore, Input.VerificationCode);
        if (!isValid)
        {
            ModelState.AddModelError("Input.VerificationCode", reason);
            return Page();
        }

        if (userStore == ManagementConstants.ManagementUserStore)
        {
            var user = await managementUserManager.FindByEmailAsync(email);
            if (user == null || !user.IsActive) return InvalidUserResult();

            user.MarkPhoneConfirmation();
            await managementUserManager.UpdateAsync(user);
            await managementUserManager.RemoveAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeName);
            await managementUserManager.RemoveAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeExpiryName);
        }
        else
        {
            var user = await userManager.FindByEmailAsync(email);
            if (user == null || !user.IsActive) return InvalidUserResult();

            user.MarkPhoneConfirmation();
            await userManager.UpdateAsync(user);
            await userManager.RemoveAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeName);
            await userManager.RemoveAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeExpiryName);
        }

        logger.Here().Information("Phone verified for {UserType} user {Email}", userStore, email);
        StatusMessage = "Your phone number has been verified.";
        return RedirectToPage("/Account/Manage/Index", new { returnUrl = Input.ReturnUrl, clientId = Input.ClientId });
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

    private async Task<bool> HasPhoneNumberAsync(string email)
    {
        var userStore = await multiUserStoreService.DetermineUserStoreByEmailAsync(email);

        if (userStore == ManagementConstants.ManagementUserStore)
        {
            var user = await managementUserManager.FindByEmailAsync(email);
            return user != null && !string.IsNullOrWhiteSpace(user.PhoneNumber);
        }

        var appUser = await userManager.FindByEmailAsync(email);
        return appUser != null && !string.IsNullOrWhiteSpace(appUser.PhoneNumber);
    }

    private async Task LoadMaskedPhoneAsync(string email)
    {
        var userStore = await multiUserStoreService.DetermineUserStoreByEmailAsync(email);

        if (userStore == ManagementConstants.ManagementUserStore)
        {
            var user = await managementUserManager.FindByEmailAsync(email);
            MaskedPhone = user != null ? MaskPhoneNumber(user.PhoneNumber) : string.Empty;
        }
        else
        {
            var user = await userManager.FindByEmailAsync(email);
            MaskedPhone = user != null ? MaskPhoneNumber(user.PhoneNumber) : string.Empty;
        }
    }

    private string GetCurrentUserEmail()
    {
        return User.FindFirstValue(ClaimTypes.Email)
            ?? User.FindFirstValue("email")
            ?? User.Identity?.Name
            ?? string.Empty;
    }

    private static string MaskPhoneNumber(string phone)
    {
        if (string.IsNullOrWhiteSpace(phone)) return string.Empty;
        if (phone.Length <= 4) return new string('*', phone.Length);
        return new string('*', phone.Length - 4) + phone[^4..];
    }

    private IActionResult InvalidUserResult()
    {
        ModelState.AddModelError(string.Empty, "Unable to process request. Account may be inactive.");
        return Page();
    }
}
