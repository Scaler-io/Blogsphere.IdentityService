using IdentityService;
using IdentityService.Extensions;
using Serilog;

var builder = WebApplication.CreateBuilder(args);
var logger = Logging.GetLogger(builder.Configuration, builder.Environment);

builder.Services.AddSingleton(x => logger);
builder.Host.UseSerilog(logger);

try
{
    var app = builder
        .ConfigureServices()
        .ConfigurePipeline();

    if (app.Environment.IsDevelopment())
    {
        // this seeding is only for the template to bootstrap the DB and users.
        // in production you will likely want a different approach.
        logger.Here().Information("Seeding database...");
        SeedData.EnsureSeedData(app);
        logger.Here().Information("Done seeding database. Exiting.");
    }

    await app.RunAsync();

}
catch (Exception ex) when (ex is not HostAbortedException)
{
    logger.Here().Fatal(ex, "Unhandled exception");
}
finally
{
    logger.Here().Information("Shut down complete");
    Log.CloseAndFlush();
}