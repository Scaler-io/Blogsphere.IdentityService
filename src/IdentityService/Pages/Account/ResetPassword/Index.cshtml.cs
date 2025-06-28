using System.Reflection.Metadata;
using System.Text;
using IdentityService.Entities;
using IdentityService.Extensions;
using IdentityService.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;

namespace IdentityService.Pages.Account.ResetPassword;

[SecurityHeaders]
[AllowAnonymous]
public partial class Index : PageModel
{
    private readonly ILogger _logger;
    private readonly UserManager<ApplicationUser> _userManager;
    public bool IsValidToken { get; set; } = true;

    [BindProperty]
    public InputModel Input { get; set; }

    public Index(ILogger logger, UserManager<ApplicationUser> userManager)
    {
        _logger = logger;
        _userManager = userManager;
    }

    public async Task<IActionResult> OnGet([FromQuery] string email, [FromQuery] string token)
    {
        if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(token))
        {
            IsValidToken = false;
            return Page();
        }

        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            IsValidToken = false;
            return Page();
        }   

        var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
        var result = await _userManager.VerifyUserTokenAsync(user, Constants.CustomPasswordResetTokenProvider, "ResetPassword", decodedToken);
        if (!result){
            IsValidToken = false;
            return Page();
        }

        TempData["Email"] = email;
        TempData["Token"] = token;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var email = TempData["Email"] as string;
        var token = TempData["Token"] as string;

        if (!ModelState.IsValid)
        {
            return Page();
        }

        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            // Don't reveal that the user does not exist
            return RedirectToPage("/Account/Login/Index");
        }

        var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
        var result = await _userManager.ResetPasswordAsync(user, decodedToken, Input.Password);
        if (result.Succeeded)
        {
            _logger.Here().Information("Password reset successful for user {Email}", email);
            return RedirectToPage("/Account/Login/Index");
        }

        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }

        return Page();
    }
}
