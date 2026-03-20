using System.Security.Claims;
using System.Text.RegularExpressions;
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

namespace IdentityService.Pages.Account.Manage.Phone;

[SecurityHeaders]
[Authorize]
[ValidateAntiForgeryToken]
public class Index(
    ILogger logger,
    UserManager<ApplicationUser> userManager,
    UserManager<ManagementUser> managementUserManager,
    IMultiUserStoreService multiUserStoreService) : PageModel
{
    private static readonly Regex IndianPhoneRegex = new(@"^(?:\+91|91)?[6-9]\d{9}$", RegexOptions.Compiled);
    private static readonly Regex IndianLocalPhoneRegex = new(@"^[6-9]\d{9}$", RegexOptions.Compiled);

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string CurrentPhone { get; set; } = string.Empty;
    public bool PhoneConfirmed { get; set; }

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

        await LoadPhoneDetailsAsync(email);
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

        if (!ModelState.IsValid)
        {
            await LoadPhoneDetailsAsync(email);
            return Page();
        }

        var sanitizedPhone = NormalizeIndianPhone(Input.PhoneNumber);

        if (string.IsNullOrWhiteSpace(sanitizedPhone))
        {
            ModelState.AddModelError("Input.PhoneNumber", "Enter a valid Indian phone number (10 digits, optional +91).");
            await LoadPhoneDetailsAsync(email);
            return Page();
        }

        var userStore = await multiUserStoreService.DetermineUserStoreByEmailAsync(email);

        if (userStore == ManagementConstants.ManagementUserStore)
        {
            var user = await managementUserManager.FindByEmailAsync(email);
            if (user == null || !user.IsActive)
            {
                ModelState.AddModelError(string.Empty, "Unable to process request. Account may be inactive.");
                return Page();
            }

            await managementUserManager.SetPhoneNumberAsync(user, sanitizedPhone);
            user.PhoneNumberConfirmed = false;
            await managementUserManager.UpdateAsync(user);
        }
        else
        {
            var user = await userManager.FindByEmailAsync(email);
            if (user == null || !user.IsActive)
            {
                ModelState.AddModelError(string.Empty, "Unable to process request. Account may be inactive.");
                return Page();
            }

            await userManager.SetPhoneNumberAsync(user, sanitizedPhone);
            user.PhoneNumberConfirmed = false;
            await userManager.UpdateAsync(user);
        }

        logger.Here().Information("Phone number updated for {UserType} user {Email}", userStore, email);
        return RedirectToPage("/Account/Manage/Phone/VerifyCode/Index", new
        {
            returnUrl = Input.ReturnUrl,
            clientId = Input.ClientId
        });
    }

    private async Task LoadPhoneDetailsAsync(string email)
    {
        var userStore = await multiUserStoreService.DetermineUserStoreByEmailAsync(email);

        if (userStore == ManagementConstants.ManagementUserStore)
        {
            var user = await managementUserManager.FindByEmailAsync(email);
            if (user != null)
            {
                CurrentPhone = MaskPhoneNumber(user.PhoneNumber);
                PhoneConfirmed = user.PhoneNumberConfirmed;
            }
        }
        else
        {
            var user = await userManager.FindByEmailAsync(email);
            if (user != null)
            {
                CurrentPhone = MaskPhoneNumber(user.PhoneNumber);
                PhoneConfirmed = user.PhoneNumberConfirmed;
            }
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

    private static string NormalizeIndianPhone(string phone)
    {
        if (string.IsNullOrWhiteSpace(phone))
        {
            return string.Empty;
        }

        var trimmed = phone.Trim();
        if (!IndianPhoneRegex.IsMatch(trimmed))
        {
            return string.Empty;
        }

        var digitsOnly = Regex.Replace(trimmed, @"\D", "");
        if (digitsOnly.StartsWith("91") && digitsOnly.Length == 12)
        {
            digitsOnly = digitsOnly[2..];
        }

        return IndianLocalPhoneRegex.IsMatch(digitsOnly) ? digitsOnly : string.Empty;
    }
}
