using IdentityService.Events;

namespace IdentityService.Services;

public interface IPublishService
{
    Task PublishAsync<TEvent>(TEvent message, string correlationId, object additionalProperties = null)
        where TEvent : NotificationEventBase;
}
