using IdentityModel;
using IdentityService.Data;
using IdentityService.Entities;
using IdentityService.Extensions;
using IdentityService.Models;
using IdentityService.Models.Enums;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using System.Security.Claims;

namespace IdentityService;

public class SeedData
{
    public async static void EnsureSeedData(WebApplication app)
    {
        using var scope = app.Services.GetRequiredService<IServiceScopeFactory>().CreateScope();

        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();

        // Do migration if it is really required
        if (IsMigrationRequired(context))
        {
            await context.Database.MigrateAsync();
        }

        // begin the transactions
        context.Database.BeginTransaction();
        // persists permissions
        await SeedPermissions(context);

        // persists role
        await SeedRoles(context, roleManager);

        // persists users
        await SeedUsers(context, userManager);

        // commit transaction
        context.Database.CommitTransaction();

    }

    private static bool IsMigrationRequired(ApplicationDbContext context) => !context.Database.GetAppliedMigrations().Any();

    private static List<ApplicationRole> GetAppRoles() => [
        new(Roles.Admin.ToString(), Roles.Admin.GetEnumMemberAttributeValue()),
        new(Roles.Editor.ToString(), Roles.Editor.GetEnumMemberAttributeValue()),
        new(Roles.Author.ToString(), Roles.Author.GetEnumMemberAttributeValue()),
        new(Roles.Subscriber.ToString(), Roles.Author.GetEnumMemberAttributeValue())
    ];

    private static List<ApplicationPermission> GetPermissions() => [
        // Blog Post Permissions
        new("post:create"),
        new("post:read"),        
        new("post:update"),     
        new("post:delete"),      
        new("post:publish"),    
        new("post:unpublish"),   

        // Comment Permissions
        new("comment:read"),     
        new("comment:write"),
        new("comment:approve"),  
        new("comment:delete"),   

        // User Management Permissions
        new("user:create"),
        new("user:read"),        
        new("user:update"),     
        new("user:delete"),     

        // Category & Tag Management
        new("category:create"),
        new("category:read"),
        new("category:update"),
        new("category:delete"),

        new("tag:create"),
        new("tag:read"),
        new("tag:update"),
        new("tag:delete"),

        // Application Settings
        new("settings:read"),     
        new("settings:update")    
    ];

    private static async Task SeedPermissions(ApplicationDbContext context)
    {
        var permissions = GetPermissions();
        if(!context.Permissions.Any())
        {
            foreach (var permission in permissions)
            {
                context.Permissions.Add(permission);
                await context.SaveChangesAsync();
            }
        }
        
    }

    private static async Task SeedRoles(ApplicationDbContext context, RoleManager<ApplicationRole> roleManager)
    {

        if (context.Roles.Any()) return;

        var roles = GetAppRoles();
        var existingPermissions = await context.Permissions.ToListAsync();

        foreach (var role in roles)
        {
            var rolePermissions = GetRolePermissions(role.Name);
            foreach (var permission in rolePermissions)
            {
                var existingPermission = existingPermissions.FirstOrDefault(p => p.Name == permission.Name);
                role.RolePermissions.Add(new(){ Permission = existingPermission });
            }
            await roleManager.CreateAsync(role);
        }
    }

    private static List<ApplicationPermission> GetRolePermissions(string roleName)
    {
        return roleName switch
        {
            "Admin" => RolePermissionMap.AdminPermissions,
            "Editor" => RolePermissionMap.EditorPermissions,
            "Author" => RolePermissionMap.AuthorPermissions,
            "Subscriber" => RolePermissionMap.SubscriberPermissions,
            _ => []
        };
    }

    private static async Task SeedUsers(ApplicationDbContext context, UserManager<ApplicationUser> userManager)
    {
        if (context.Users.Any()) return; 

        var roles = GetAppRoles();
        var adminUser = new ApplicationUser("sharthak123", "Sharthak", "Mallik", "sharthak@blogshepere.com");
        var editorUser = new ApplicationUser("john123", "John", "Doe", "john@blogshepere.com");
        var authorUser = new ApplicationUser("david100", "David", "Warn", "david@blogshepere.com");
        var subscriberUser = new ApplicationUser("henry200", "Henry", "Matt", "henry@blogshepere.com");

        authorUser.SetProfileDetails("A simple bio");

        try
        {
            await userManager.CreateAsync(adminUser, "P@ssw0rd");
            await userManager.CreateAsync(editorUser, "P@ssw0rd");
            await userManager.CreateAsync(authorUser, "P@ssw0rd");
            await userManager.CreateAsync(subscriberUser, "P@ssw0rd");

            await AddToClaim(adminUser, userManager, roles.Where(x => x.Name == Roles.Admin.ToString()).ToList(),RolePermissionMap.AdminPermissions);

            await AddToClaim(editorUser, userManager,
                roles.Where(x => x.Name == Roles.Editor.ToString()).ToList(),
                RolePermissionMap.EditorPermissions);

            await AddToClaim(authorUser, userManager,
                roles.Where(x => x.Name == Roles.Author.ToString()).ToList(),
                RolePermissionMap.AuthorPermissions);

            await AddToClaim(subscriberUser, userManager,
                roles.Where(x => x.Name == Roles.Subscriber.ToString()).ToList(),
                RolePermissionMap.SubscriberPermissions);

            await userManager.AddToRoleAsync(adminUser, Roles.Admin.ToString());
            await userManager.AddToRoleAsync(editorUser, Roles.Editor.ToString());
            await userManager.AddToRoleAsync(authorUser, Roles.Author.ToString());
            await userManager.AddToRoleAsync(subscriberUser, Roles.Subscriber.ToString());
        }
        catch (Exception)
        {
            // exception handling
        }
    }

    private static async Task AddToClaim(ApplicationUser user, UserManager<ApplicationUser> userManager,
        List<ApplicationRole> roles,
        List<ApplicationPermission> permissions)
    {
        await userManager.AddClaimsAsync(user, [
            new Claim(JwtClaimTypes.Name, user.UserName),
            new Claim(JwtClaimTypes.GivenName, user.FirstName),
            new Claim(JwtClaimTypes.FamilyName, user.Lastname),
            new Claim(JwtClaimTypes.Email, user.Email),
            new Claim(JwtClaimTypes.Role, JsonConvert.SerializeObject(string.Join(",", roles.Select(r => r.Name).ToList()))),
            new Claim("Permissions", JsonConvert.SerializeObject(string.Join(",", permissions.Select(x => x.Name).ToList())))
        ]);
    }

}
