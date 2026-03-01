using Duende.IdentityServer.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdentityService.Pages.Account.ForgotPassword;

[AllowAnonymous]
[SecurityHeaders]
[ValidateAntiForgeryToken]
public class Status : PageModel
{
    public IActionResult OnGet()
    {
        if(User.IsAuthenticated())
        {
            return Redirect("~/");
        }
        return Page();
    }
}
