// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdentityService.Pages.Device;

[SecurityHeaders]
[Authorize]
[ValidateAntiForgeryToken]
public class SuccessModel : PageModel
{
    public void OnGet()
    {
    }
}
