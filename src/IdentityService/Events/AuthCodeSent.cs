using IdentityService.Events;
using IdentityService.Models.Enums;

namespace Contracts.Events;

public class AuthCodeSent : NotificationEventBase
{
    public string Email { get; set; }
    public string Code { get; set; }
    protected override NotificationType NotificationType { get; set;} = NotificationType.AuthCodeSent;
}
