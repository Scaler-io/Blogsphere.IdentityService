using IdentityService.Configurations;
using IdentityService.Data;
using IdentityService.Entities;
using IdentityService.Models;
using IdentityService.Security;
using IdentityService.Services;
using MassTransit;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json.Converters;
using Serilog;

namespace IdentityService;

internal static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        builder.Services.AddRazorPages()
            .AddNewtonsoftJson(config =>
            {
                config.UseCamelCasing(true);
                config.SerializerSettings.Converters.Add(new StringEnumConverter());
            });

        // use sql sever as underlying database technology
        builder.Services.AddDbContext<ApplicationDbContext>(options =>
        {
            options.UseSqlServer(builder.Configuration.GetConnectionString("Sqlserver"))
            .LogTo(System.Console.WriteLine, LogLevel.Information);
        });

        builder.Services.AddDbContext<DataProtectionKeyContext>(options =>
        {
            options.UseSqlServer(builder.Configuration.GetConnectionString("Sqlserver"))
            .LogTo(System.Console.WriteLine, LogLevel.Information);
        });

        // Key store for data hash
        var appRootPath = Directory.GetCurrentDirectory();
        builder.Services.AddDataProtection()
            // .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(appRootPath, "keys")))
            .PersistKeysToDbContext<DataProtectionKeyContext>()
            .SetApplicationName("blogsphere");


        builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
        {
            options.SignIn.RequireConfirmedEmail = true;
            options.Tokens.EmailConfirmationTokenProvider = Constants.CustomEmailTokenProvider;
            options.Tokens.PasswordResetTokenProvider = Constants.CustomPasswordResetTokenProvider;
            options.Tokens.ProviderMap[Constants.CustomTwoFactorTokenProvider] = new TokenProviderDescriptor(typeof(TwoFactorAuthTokenProvider));
        })
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders()
        .AddTokenProvider<PasswordResetTokenProvider<ApplicationUser>>(Constants.CustomPasswordResetTokenProvider)  
        .AddTokenProvider<EmailConfirmationTokenProvider<ApplicationUser>>(Constants.CustomEmailTokenProvider)
        .AddTokenProvider<TwoFactorAuthTokenProvider>(Constants.CustomTwoFactorTokenProvider);

        // Configure token provider options
        builder.Services.Configure<DataProtectionTokenProviderOptions>(options =>
        {
            options.TokenLifespan = TimeSpan.FromHours(1);
        });

        builder.Services.Configure<PasswordResetTokenProviderOptions>(options =>
        {
            options.TokenLifespan = TimeSpan.FromHours(1);
        });

        builder.Services.Configure<EmailConfirmationTokenProviderOptions>(options =>
        {
            options.TokenLifespan = TimeSpan.FromHours(1);
        });

        builder.Services
            .AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;

                // see https://docs.duendesoftware.com/identityserver/v6/fundamentals/resources/
                options.EmitStaticAudienceClaim = true;
                options.Discovery.CustomEntries.Add("jwks_uri", "https://localhost:5000/.well-known/jwks");
            })
            .AddInMemoryIdentityResources(Config.IdentityResources)
            .AddInMemoryApiScopes(Config.ApiScopes)
            .AddInMemoryApiResources(Config.ApiResources)
            .AddInMemoryClients(Config.Clients)
            .AddAspNetIdentity<ApplicationUser>()
            .AddProfileService<UserProfileService>()
            .AddDeveloperSigningCredential();

        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.SameSite = SameSiteMode.Lax;
        });

        builder.Services.AddMassTransit(configuration => {
            configuration.SetEndpointNameFormatter(new KebabCaseEndpointNameFormatter("identity", false));
            configuration.UsingRabbitMq((context, cfg) => {
                var eventBus = builder.Configuration.GetSection(EventBusConfigurations.OptionName).Get<EventBusConfigurations>();
                cfg.Host(eventBus.Host, eventBus.VirtualHost, host => 
                {
                    host.Username(eventBus.Username);
                    host.Password(eventBus.Password);
                });
                
                cfg.ConfigureEndpoints(context);
            });
        });

        builder.Services.AddCors(options =>
        {
            options.AddPolicy(Constants.AppCorsPolicy, policy =>
            {
                policy.WithOrigins("http://localhost:4200").AllowAnyHeader().AllowAnyMethod();
            });
        });

        builder.Services.AddScoped<IPublishService, PublishService>();

        return builder.Build();
    }

    public static WebApplication ConfigurePipeline(this WebApplication app)
    {
        app.UseSerilogRequestLogging();

        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }

        app.UseStaticFiles();
        app.UseCors(Constants.AppCorsPolicy);
        app.UseRouting();
        app.UseIdentityServer();
        app.UseAuthorization();

        app.MapRazorPages()
            .RequireAuthorization();

        return app;
    }
}