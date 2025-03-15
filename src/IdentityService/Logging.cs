using Destructurama;
using IdentityService.Configurations;
using Serilog;
using Serilog.Core;
using Serilog.Events;

namespace IdentityService;

public class Logging
{
    public static ILogger GetLogger(IConfiguration configuration, IWebHostEnvironment environment)
    {
        var loggingConfigurations = configuration.GetSection(LoggingConfigurations.LoggingConfigName).Get<LoggingConfigurations>();
        var appConfigurations = configuration.GetSection(AppConfigurations.AppConfigName).Get<AppConfigurations>();
        var elasticConfigurations = configuration.GetSection(ElasticSearchConfigurations.ElasticConfigName).Get<ElasticSearchConfigurations>();

        var logIndexPattern = $"Blogsphere.IdentityServer.{environment.EnvironmentName}";

        Enum.TryParse(loggingConfigurations?.Console.LogLevel, false, out LogEventLevel minimumEventLevel);

        var loggerConfiguration = new LoggerConfiguration()
            .MinimumLevel.ControlledBy(new LoggingLevelSwitch(minimumEventLevel))
                .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
                .MinimumLevel.Override("Microsoft.Hosting.Lifetime", LogEventLevel.Information)
                .MinimumLevel.Override("System", LogEventLevel.Warning)
                .Enrich.FromLogContext()
                .Enrich.WithProperty(nameof(Environment.MachineName), Environment.MachineName)
                .Enrich.WithProperty(nameof(appConfigurations.ApplicationIdentifier), appConfigurations.ApplicationIdentifier)
                .Enrich.WithProperty(nameof(appConfigurations.ApplicationEnvironment), appConfigurations.ApplicationEnvironment);

        if (loggingConfigurations.Console.Enabled)
        {
            loggerConfiguration.WriteTo.Console(minimumEventLevel, loggingConfigurations?.LogOutputTemplate);
        }
        if (loggingConfigurations.Elastic.Enabled)
        {
            loggerConfiguration.WriteTo.Elasticsearch(elasticConfigurations.Uri, logIndexPattern);
        }

        return loggerConfiguration
               .Destructure
               .UsingAttributes()
               .CreateLogger();
    }
}
