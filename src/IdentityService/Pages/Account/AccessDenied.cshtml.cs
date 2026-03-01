// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdentityService.Pages.Account;

[ValidateAntiForgeryToken]
public class AccessDeniedModel : PageModel
{
    public void OnGet()
    {
    }
}
