using IdentityService.Events;
using IdentityService.Models.Enums;

namespace Contracts.Events;

public class PasswordResetOneTimeCodeSent : NotificationEventBase
{
    public string Email { get; set; } = string.Empty;
    public string Code { get; set; } = string.Empty;
    protected override NotificationType NotificationType { get; set; } = NotificationType.PasswordResetOneTimeCodeSent;
}
