using System.ComponentModel.DataAnnotations;

namespace IdentityService.Pages.Account.Manage.TwoFactor;

public class InputModel
{
    public string ReturnUrl { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Action to perform: "enable", "requestDisableCode", "confirmDisable"
    /// </summary>
    public string Action { get; set; } = string.Empty;

    [Display(Name = "Verification Code")]
    public string VerificationCode { get; set; } = string.Empty;
}
