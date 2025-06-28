using IdentityService.Events;
using IdentityService.Models.Enums;

namespace Contracts.Events;

public class PasswordResetInstructionSent : NotificationEventBase
{
    public string Email { get; set; }
    protected override NotificationType NotificationType { get; set; } = NotificationType.PasswordResetInstructionSent;
}
