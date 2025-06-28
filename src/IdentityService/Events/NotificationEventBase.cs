using IdentityService.Models.Enums;

namespace IdentityService.Events;

public abstract class NotificationEventBase
{
    public DateTime CreatedOn { get; set; }
    public string CorrelationId { get; set; }
    public object AdditionalProperties { get; set; }
    protected abstract NotificationType NotificationType { get; set; }
}
