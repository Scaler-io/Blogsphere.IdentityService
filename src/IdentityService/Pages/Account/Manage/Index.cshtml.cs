using System.Security.Claims;
using IdentityService.Entities;
using IdentityService.Extensions;
using IdentityService.Management.Entities;
using IdentityService.Management.Models;
using IdentityService.Management.Services;
using IdentityService.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdentityService.Pages.Account.Manage;

[SecurityHeaders]
[Authorize]
[ValidateAntiForgeryToken]
public class Index(
    ILogger logger,
    UserManager<ApplicationUser> userManager,
    UserManager<ManagementUser> managementUserManager,
    IMultiUserStoreService multiUserStoreService) : PageModel
{
    public string ReturnUrl { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public bool TwoFactorEnabled { get; set; }
    public string MaskedPhone { get; set; } = string.Empty;
    public bool PhoneConfirmed { get; set; }
    public string UserEmail { get; set; } = string.Empty;

    [TempData]
    public string StatusMessage { get; set; } = string.Empty;

    public async Task<IActionResult> OnGet([FromQuery] string returnUrl = null, [FromQuery] string clientId = null)
    {
        ReturnUrl = ReturnUrlGuard.NormalizeForClientApp(returnUrl, clientId);
        ClientId = clientId ?? string.Empty;

        var email = GetCurrentUserEmail();
        if (string.IsNullOrWhiteSpace(email))
        {
            return RedirectToPage("/Account/Login/Index", new { returnUrl = ReturnUrl });
        }

        UserEmail = email;
        await LoadUserDetailsAsync(email);

        return Page();
    }

    private async Task LoadUserDetailsAsync(string email)
    {
        var userStore = await multiUserStoreService.DetermineUserStoreByEmailAsync(email);

        if (userStore == ManagementConstants.ManagementUserStore)
        {
            var user = await managementUserManager.FindByEmailAsync(email);
            if (user != null)
            {
                TwoFactorEnabled = await managementUserManager.GetTwoFactorEnabledAsync(user);
                var phone = await managementUserManager.GetPhoneNumberAsync(user);
                MaskedPhone = MaskPhoneNumber(phone);
                PhoneConfirmed = user.PhoneNumberConfirmed;
            }
        }
        else
        {
            var user = await userManager.FindByEmailAsync(email);
            if (user != null)
            {
                TwoFactorEnabled = await userManager.GetTwoFactorEnabledAsync(user);
                var phone = await userManager.GetPhoneNumberAsync(user);
                MaskedPhone = MaskPhoneNumber(phone);
                PhoneConfirmed = user.PhoneNumberConfirmed;
            }
        }

        logger.Here().Information("Loaded account manage page for {Email}", email);
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
}
