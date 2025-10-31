using IdentityService.Configurations;
using IdentityService.Data;
using IdentityService.Entities;
using IdentityService.Models;
using IdentityService.Security;
using IdentityService.Services;
using IdentityService.Management.Data;
using IdentityService.Management.Entities;
using IdentityService.Management.Security;
using IdentityService.Management.Models;
using IdentityService.Management.Services;
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
        // Configure Razor Pages with JSON serialization
        builder.Services.AddRazorPages()
            .AddNewtonsoftJson(config =>
            {
                config.UseCamelCasing(true);
                config.SerializerSettings.Converters.Add(new StringEnumConverter());
            });

        // Configure Database Contexts
        ConfigureDatabaseContexts(builder);

        // Configure Data Protection
        ConfigureDataProtection(builder);

        // Configure Identity Systems
        ConfigureApplicationUserIdentity(builder);
        ConfigureManagementUserIdentity(builder);

        // Configure IdentityServer
        ConfigureIdentityServer(builder);

        // Configure Application Services
        ConfigureApplicationServices(builder);

        // Configure External Services
        ConfigureExternalServices(builder);

        return builder.Build();
    }

    private static void ConfigureDatabaseContexts(WebApplicationBuilder builder)
    {
        var connectionString = builder.Configuration.GetConnectionString("Sqlserver");
        
        // Main Application Database
        builder.Services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(connectionString));

        // Management Database with separate schema
        builder.Services.AddDbContext<ManagementDbContext>(options =>
            options.UseSqlServer(connectionString, 
                sqlOptions => sqlOptions.MigrationsHistoryTable("__EFMigrationsHistory", "Management")));

        // Data Protection Database
        builder.Services.AddDbContext<DataProtectionKeyContext>(options =>
            options.UseSqlServer(connectionString));
    }

    private static void ConfigureDataProtection(WebApplicationBuilder builder)
    {
        builder.Services.AddDataProtection()
            .PersistKeysToDbContext<DataProtectionKeyContext>()
            .SetApplicationName("blogsphere")
            .SetDefaultKeyLifetime(TimeSpan.FromDays(90)); // Keys valid for 90 days
    }

    private static void ConfigureApplicationUserIdentity(WebApplicationBuilder builder)
    {
        // Configure ApplicationUser Identity with proper token providers
        builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
        {
            // Sign-in requirements
            options.SignIn.RequireConfirmedEmail = true;
            
            // Password requirements
            options.Password.RequireDigit = true;
            options.Password.RequiredLength = 8;
            options.Password.RequireNonAlphanumeric = true;
            options.Password.RequireUppercase = true;
            options.Password.RequireLowercase = true;
            
            // Token provider configuration
            options.Tokens.EmailConfirmationTokenProvider = Constants.CustomEmailTokenProvider;
            options.Tokens.PasswordResetTokenProvider = Constants.CustomPasswordResetTokenProvider;
            
            // Register password reset provider as two-factor provider for ResetPasswordAsync compatibility
            options.Tokens.ProviderMap[Constants.CustomPasswordResetTokenProvider] = 
                new TokenProviderDescriptor(typeof(PasswordResetTokenProvider<ApplicationUser>));
        })
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders()
        .AddTokenProvider<PasswordResetTokenProvider<ApplicationUser>>(Constants.CustomPasswordResetTokenProvider)
        .AddTokenProvider<EmailConfirmationTokenProvider<ApplicationUser>>(Constants.CustomEmailTokenProvider)
        .AddTokenProvider<TwoFactorAuthTokenProvider>(Constants.CustomTwoFactorTokenProvider);

        // Configure ApplicationUser token provider options
        builder.Services.Configure<PasswordResetTokenProviderOptions>(options =>
            options.TokenLifespan = TimeSpan.FromHours(1));
        
        builder.Services.Configure<EmailConfirmationTokenProviderOptions>(options =>
            options.TokenLifespan = TimeSpan.FromHours(1));
    }

    private static void ConfigureManagementUserIdentity(WebApplicationBuilder builder)
    {
        // Configure ManagementUser Identity using AddIdentityCore to avoid conflicts
        builder.Services.AddIdentityCore<ManagementUser>(options =>
        {
            // Sign-in requirements
            options.SignIn.RequireConfirmedEmail = true;
            
            // Password requirements
            options.Password.RequireDigit = true;
            options.Password.RequiredLength = 8;
            options.Password.RequireNonAlphanumeric = true;
            options.Password.RequireUppercase = true;
            options.Password.RequireLowercase = true;
            
            // Token provider configuration
            options.Tokens.EmailConfirmationTokenProvider = TokenOptions.DefaultEmailProvider;
            options.Tokens.PasswordResetTokenProvider = ManagementConstants.ManagementPasswordResetTokenProvider;
            
            // Register password reset provider as two-factor provider for ResetPasswordAsync compatibility
            options.Tokens.ProviderMap[ManagementConstants.ManagementPasswordResetTokenProvider] = 
                new TokenProviderDescriptor(typeof(ManagementPasswordResetTokenProvider<ManagementUser>));
        })
        .AddRoles<ManagementRole>()
        .AddEntityFrameworkStores<ManagementDbContext>()
        .AddDefaultTokenProviders()
        .AddTokenProvider<ManagementPasswordResetTokenProvider<ManagementUser>>(ManagementConstants.ManagementPasswordResetTokenProvider)
        .AddTokenProvider<ManagementEmailConfirmationTokenProvider<ManagementUser>>(ManagementConstants.ManagementEmailTokenProvider)
        .AddTokenProvider<ManagementTwoFactorAuthTokenProvider>(ManagementConstants.ManagementTwoFactorTokenProvider)
        .AddSignInManager<SignInManager<ManagementUser>>();

        // Configure ManagementUser token provider options
        builder.Services.Configure<ManagementPasswordResetTokenProviderOptions>(options =>
            options.TokenLifespan = TimeSpan.FromHours(1));
        
        builder.Services.Configure<ManagementEmailConfirmationTokenProviderOptions>(options =>
            options.TokenLifespan = TimeSpan.FromHours(1));
    }

    private static void ConfigureIdentityServer(WebApplicationBuilder builder)
    {
        builder.Services.AddIdentityServer(options =>
        {
            // Event configuration
            options.Events.RaiseErrorEvents = true;
            options.Events.RaiseInformationEvents = true;
            options.Events.RaiseFailureEvents = true;
            options.Events.RaiseSuccessEvents = true;

            // Resource configuration
            options.EmitStaticAudienceClaim = true;
            
            // Key management configuration for containerized environments
            options.KeyManagement.Enabled = true;
            options.KeyManagement.RotationInterval = TimeSpan.FromDays(30);
        })
        .AddInMemoryIdentityResources(Config.IdentityResources)
        .AddInMemoryApiScopes(Config.ApiScopes)
        .AddInMemoryApiResources(Config.ApiResources)
        .AddInMemoryClients(Config.Clients)
        .AddAspNetIdentity<ApplicationUser>()
        .AddProfileService<UserProfileService>()
        .AddDeveloperSigningCredential(persistKey: false); // Don't persist file-based keys

        // Register the custom resource owner password validator
        builder.Services.AddScoped<Duende.IdentityServer.Validation.IResourceOwnerPasswordValidator, Services.MultiUserResourceOwnerPasswordValidator>();

        // Configure application cookies
        builder.Services.ConfigureApplicationCookie(options =>
            options.Cookie.SameSite = SameSiteMode.Lax);
    }

    private static void ConfigureApplicationServices(WebApplicationBuilder builder)
    {
        // Core application services
        builder.Services.AddScoped<IPublishService, PublishService>();
        
        // Management services
        builder.Services.AddScoped<IdentityService.Management.Services.IMultiUserStoreService, 
            IdentityService.Management.Services.MultiUserStoreService>();
        // builder.Services.AddScoped<IdentityService.Management.Services.ManagementProfileService>();
        
        // Authentication services
        builder.Services.AddScoped<IApplicationUserAuthenticationService, ApplicationUserAuthenticationService>();
        builder.Services.AddScoped<IManagementUserAuthenticationService, ManagementUserAuthenticationService>();
    }

    private static void ConfigureExternalServices(WebApplicationBuilder builder)
    {
        // Configure MassTransit for event publishing
        builder.Services.AddMassTransit(configuration =>
        {
            configuration.SetEndpointNameFormatter(new KebabCaseEndpointNameFormatter("identity", false));
            configuration.UsingRabbitMq((context, cfg) =>
            {
                var eventBus = builder.Configuration.GetSection(EventBusConfigurations.OptionName)
                    .Get<EventBusConfigurations>();
                cfg.Host(eventBus.Host, eventBus.VirtualHost, host =>
                {
                    host.Username(eventBus.Username);
                    host.Password(eventBus.Password);
                });
                cfg.ConfigureEndpoints(context);
            });
        });

        // Configure CORS
        builder.Services.AddCors(options =>
        {
            options.AddPolicy(Constants.AppCorsPolicy, policy =>
                policy.WithOrigins("http://localhost:4200")
                      .AllowAnyHeader()
                      .AllowAnyMethod());
        });
    }

    public static WebApplication ConfigurePipeline(this WebApplication app)
    {
        // Configure request logging
        app.UseSerilogRequestLogging();

        // Configure development environment
        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }

        // Configure middleware pipeline
        app.UseStaticFiles();
        app.UseCors(Constants.AppCorsPolicy);
        app.UseRouting();
        app.UseIdentityServer();
        app.UseAuthorization();

        // Configure endpoints
        app.MapRazorPages().RequireAuthorization();

        return app;
    }
}