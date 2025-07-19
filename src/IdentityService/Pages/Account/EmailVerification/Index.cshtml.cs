using System.Text;
using IdentityService.Entities;
using IdentityService.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;

namespace IdentityService.Pages.EmailVerification;

[SecurityHeaders]
[AllowAnonymous]
public class Index(UserManager<ApplicationUser> userManager, ILogger logger) : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager = userManager;
    private readonly ILogger _logger = logger;

    [BindProperty]
    public bool EmailVerificationCompleted { get; set; }
    [BindProperty]
    public bool EmailVerificationFailed { get; set; }
    [BindProperty]
    public string FailureMessage { get; set; }
    [BindProperty]
    public string UserEmail { get; set; }

    public async Task<IActionResult> OnGetAsync([FromQuery] string userId, [FromQuery] string token)
    {
        if(string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
        {
            _logger.Here().Error("No user id found in the url. Url must be invalid");
            EmailVerificationFailed = true;
            FailureMessage = "Seems like the url was tampered. Please connect to support team";
            return Page();
        }
        
        var user = await _userManager.FindByIdAsync(userId);
        if(user == null)
        {
            _logger.Here().Error("No user found with id {UserId}", userId);
            EmailVerificationFailed = true;
            FailureMessage = "Seems like the url was tampered. Please connect to support team";
            return Page();
        }
        if (user.EmailConfirmed)
        {
            _logger.Here().Error("User email is already activated {email}", user.Email);
            EmailVerificationFailed = true;
            FailureMessage = "Seems like the url was tampered. Please connect to support team";
            return Page();
        }

        var result = await _userManager.ConfirmEmailAsync(user, Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token)));
        if(!result.Succeeded)
        {
            _logger.Here().Error("Failed to confirm email for the user {username}", user.UserName);
            EmailVerificationFailed = true;
            FailureMessage = "Failed to confirm email. Please connect to our support team";
            return Page();
        }

        _logger.Here().Information("user email successfully verified - {userid}", userId);
        FailureMessage = "";
        EmailVerificationFailed = false;
        EmailVerificationCompleted = true;
        UserEmail = user.Email;
        // Default state - show pending verification message    
        return Page();
    }
} 