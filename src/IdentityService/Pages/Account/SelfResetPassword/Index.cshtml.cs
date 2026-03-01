using System.Security.Claims;
using IdentityService.Extensions;
using IdentityService.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdentityService.Pages.Account.SelfResetPassword;

[SecurityHeaders]
[Authorize]
[ValidateAntiForgeryToken]
public class Index : PageModel
{
    [BindProperty]
    public InputModel Input { get; set; } = new();

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

    private string GetCurrentUserEmail()
    {
        return User.FindFirstValue(ClaimTypes.Email)
            ?? User.FindFirstValue("email")
            ?? User.Identity?.Name
            ?? string.Empty;
    }
}
