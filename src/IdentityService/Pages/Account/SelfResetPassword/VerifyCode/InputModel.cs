using System.ComponentModel.DataAnnotations;

namespace IdentityService.Pages.Account.SelfResetPassword.VerifyCode;

public class InputModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    public string ReturnUrl { get; set; } = string.Empty;

    public string ClientId { get; set; } = string.Empty;

    public string OneTimeCode { get; set; } = string.Empty;

    public string Action { get; set; } = string.Empty;
}
