using IdentityService.Events;
using IdentityService.Extensions;
using MassTransit;

namespace IdentityService.Services;

public class PublishService(ILogger logger, IPublishEndpoint publishEndpoint) : IPublishService
{
    private readonly ILogger _logger = logger;
    private readonly IPublishEndpoint _publishEndpoint = publishEndpoint;

    public async Task PublishAsync<TEvent>(TEvent message, string correlationId, object additionalProperties = null)
        where TEvent : NotificationEventBase
    {
        _logger.Here().MethodEnterd();
        message.CorrelationId = correlationId;
        message.AdditionalProperties = additionalProperties;

        await _publishEndpoint.Publish(message);

        _logger.Here()
        .WithCorrelationId(correlationId)
        .Information("Successfully published {messageType} event message", typeof(TEvent).Name);
    }
}
