using IdentityService.Management.Entities;
using IdentityService.Management.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace IdentityService.Management.Data;

public static class ManagementSeedData
{
    public static async Task InitializeAsync(IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<ManagementDbContext>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ManagementUser>>();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<ManagementRole>>();
        var logger = scope.ServiceProvider.GetRequiredService<ILogger>();

        await SeedAsync(context, userManager, roleManager, logger);
    }

    public static async Task SeedAsync(ManagementDbContext context, 
        UserManager<ManagementUser> userManager, 
        RoleManager<ManagementRole> roleManager,
        ILogger logger)
    {
        logger.Information("Starting management data seeding");
        
        // Apply any pending migrations
        await context.Database.MigrateAsync();
        
        // Seed roles
        await SeedRolesAsync(roleManager, logger);
        
        // Seed users
        await SeedUsersAsync(userManager, logger);
        
        logger.Information("Management data seeding completed");
    }

    private static async Task SeedRolesAsync(RoleManager<ManagementRole> roleManager, ILogger logger)
    {
        logger.Information("Seeding management roles");
        
        var roles = new[]
        {
            new ManagementRole { Name = "SuperAdmin", Description = "Super Administrator with full access" },
            new ManagementRole { Name = "Admin", Description = "Administrator with limited access" },
            new ManagementRole { Name = "Moderator", Description = "Moderator with content management access" },
            new ManagementRole { Name = "Support", Description = "Support staff with user assistance access" }
        };

        foreach (var role in roles)
        {
            if (!await roleManager.RoleExistsAsync(role.Name))
            {
                await roleManager.CreateAsync(role);
                logger.Information("Created role: {RoleName}", role.Name);
            }
        }
    }

    private static async Task SeedUsersAsync(UserManager<ManagementUser> userManager, ILogger logger)
    {
        logger.Information("Seeding management users");
        
        var users = new[]
        {
            new ManagementUser("Super", "Admin", "superadmin@blogsphere.com", "IT") { JobTitle = "System Administrator" },
            new ManagementUser("Admin", "User", "admin@blogsphere.com", "IT") { JobTitle = "Administrator" }
        };

        foreach (var user in users)
        {
            if (await userManager.FindByEmailAsync(user.Email) == null)
            {
                var result = await userManager.CreateAsync(user, "Admin@123");
                if (result.Succeeded)
                {
                    // Directly confirm email instead of using token-based confirmation
                    user.EmailConfirmed = true;
                    await userManager.UpdateAsync(user);
                    logger.Information("Created and confirmed management user: {Email}", user.Email);
                }
                else
                {
                    logger.Error("Failed to create management user {Email}: {Errors}", user.Email, string.Join(", ", result.Errors.Select(e => e.Description)));
                }
            }
            else
            {
                // Ensure existing user has email confirmed
                var existingUser = await userManager.FindByEmailAsync(user.Email);
                if (existingUser != null && !existingUser.EmailConfirmed)
                {
                    existingUser.EmailConfirmed = true;
                    await userManager.UpdateAsync(existingUser);
                    logger.Information("Confirmed email for existing management user: {Email}", user.Email);
                }
            }
        }
    }
}

// Management Role Permission Map - Similar to RolePermissionMap for ApplicationUser
public static class ManagementRolePermissionMap
{
    public static List<ManagementPermission> AdminPermissions =>
    [
        // User Management
        new("user:view", "View user details", ManagementConstants.UserManagementCategory),
        new("user:create", "Create new users", ManagementConstants.UserManagementCategory),
        new("user:update", "Update user details", ManagementConstants.UserManagementCategory),
        new("user:manage-roles", "Manage user roles", ManagementConstants.UserManagementCategory),
        
        // Content Management
        new("content:view", "View content", ManagementConstants.ContentManagementCategory),
        new("content:create", "Create content", ManagementConstants.ContentManagementCategory),
        new("content:update", "Update content", ManagementConstants.ContentManagementCategory),
        new("content:delete", "Delete content", ManagementConstants.ContentManagementCategory),
        new("content:moderate", "Moderate content", ManagementConstants.ContentManagementCategory),
        new("content:publish", "Publish content", ManagementConstants.ContentManagementCategory),
        new("content:unpublish", "Unpublish content", ManagementConstants.ContentManagementCategory),
        
        // Blog Management
        new("blog:view", "View blog posts", ManagementConstants.ContentManagementCategory),
        new("blog:create", "Create blog posts", ManagementConstants.ContentManagementCategory),
        new("blog:update", "Update blog posts", ManagementConstants.ContentManagementCategory),
        new("blog:delete", "Delete blog posts", ManagementConstants.ContentManagementCategory),
        new("blog:publish", "Publish blog posts", ManagementConstants.ContentManagementCategory),
        new("blog:unpublish", "Unpublish blog posts", ManagementConstants.ContentManagementCategory),
        
        // Comment Management
        new("comment:view", "View comments", ManagementConstants.ContentManagementCategory),
        new("comment:moderate", "Moderate comments", ManagementConstants.ContentManagementCategory),
        new("comment:delete", "Delete comments", ManagementConstants.ContentManagementCategory),
        
        // Category & Tag Management
        new("category:view", "View categories", ManagementConstants.ContentManagementCategory),
        new("category:create", "Create categories", ManagementConstants.ContentManagementCategory),
        new("category:update", "Update categories", ManagementConstants.ContentManagementCategory),
        new("category:delete", "Delete categories", ManagementConstants.ContentManagementCategory),
        
        new("tag:view", "View tags", ManagementConstants.ContentManagementCategory),
        new("tag:create", "Create tags", ManagementConstants.ContentManagementCategory),
        new("tag:update", "Update tags", ManagementConstants.ContentManagementCategory),
        new("tag:delete", "Delete tags", ManagementConstants.ContentManagementCategory),
        
        // Role Management
        new("role:view", "View roles", ManagementConstants.RoleManagementCategory),
        new("role:create", "Create roles", ManagementConstants.RoleManagementCategory),
        new("role:update", "Update roles", ManagementConstants.RoleManagementCategory),
        new("role:assign-permissions", "Assign permissions to roles", ManagementConstants.RoleManagementCategory),
        
        // System Management
        new("system:view-logs", "View system logs", ManagementConstants.SystemManagementCategory),
        new("system:view-analytics", "View analytics", ManagementConstants.SystemManagementCategory),
        
        // Support
        new("support:view-tickets", "View support tickets", ManagementConstants.SupportCategory),
        new("support:resolve-tickets", "Resolve support tickets", ManagementConstants.SupportCategory),
        new("support:manage-tickets", "Manage support tickets", ManagementConstants.SupportCategory)
    ];

    public static List<ManagementPermission> ManagerPermissions =>
    [
        // User Management
        new("user:view", "View user details", ManagementConstants.UserManagementCategory),
        new("user:create", "Create new users", ManagementConstants.UserManagementCategory),
        new("user:update", "Update user details", ManagementConstants.UserManagementCategory),
        new("user:manage-roles", "Manage user roles", ManagementConstants.UserManagementCategory),
        
        // Content Management
        new("content:view", "View content", ManagementConstants.ContentManagementCategory),
        new("content:create", "Create content", ManagementConstants.ContentManagementCategory),
        new("content:update", "Update content", ManagementConstants.ContentManagementCategory),
        new("content:delete", "Delete content", ManagementConstants.ContentManagementCategory),
        new("content:moderate", "Moderate content", ManagementConstants.ContentManagementCategory),
        new("content:publish", "Publish content", ManagementConstants.ContentManagementCategory),
        new("content:unpublish", "Unpublish content", ManagementConstants.ContentManagementCategory),
        
        // Blog Management
        new("blog:view", "View blog posts", ManagementConstants.ContentManagementCategory),
        new("blog:create", "Create blog posts", ManagementConstants.ContentManagementCategory),
        new("blog:update", "Update blog posts", ManagementConstants.ContentManagementCategory),
        new("blog:delete", "Delete blog posts", ManagementConstants.ContentManagementCategory),
        new("blog:publish", "Publish blog posts", ManagementConstants.ContentManagementCategory),
        new("blog:unpublish", "Unpublish blog posts", ManagementConstants.ContentManagementCategory),
        
        // Comment Management
        new("comment:view", "View comments", ManagementConstants.ContentManagementCategory),
        new("comment:moderate", "Moderate comments", ManagementConstants.ContentManagementCategory),
        new("comment:delete", "Delete comments", ManagementConstants.ContentManagementCategory),
        
        // Category & Tag Management
        new("category:view", "View categories", ManagementConstants.ContentManagementCategory),
        new("category:create", "Create categories", ManagementConstants.ContentManagementCategory),
        new("category:update", "Update categories", ManagementConstants.ContentManagementCategory),
        new("category:delete", "Delete categories", ManagementConstants.ContentManagementCategory),
        
        new("tag:view", "View tags", ManagementConstants.ContentManagementCategory),
        new("tag:create", "Create tags", ManagementConstants.ContentManagementCategory),
        new("tag:update", "Update tags", ManagementConstants.ContentManagementCategory),
        new("tag:delete", "Delete tags", ManagementConstants.ContentManagementCategory),
        
        // Analytics
        new("system:view-analytics", "View analytics", ManagementConstants.SystemManagementCategory)
    ];

    public static List<ManagementPermission> ModeratorPermissions =>
    [
        // Content Management
        new("content:view", "View content", ManagementConstants.ContentManagementCategory),
        new("content:create", "Create content", ManagementConstants.ContentManagementCategory),
        new("content:update", "Update content", ManagementConstants.ContentManagementCategory),
        new("content:moderate", "Moderate content", ManagementConstants.ContentManagementCategory),
        new("content:publish", "Publish content", ManagementConstants.ContentManagementCategory),
        new("content:unpublish", "Unpublish content", ManagementConstants.ContentManagementCategory),
        
        // Blog Management
        new("blog:view", "View blog posts", ManagementConstants.ContentManagementCategory),
        new("blog:create", "Create blog posts", ManagementConstants.ContentManagementCategory),
        new("blog:update", "Update blog posts", ManagementConstants.ContentManagementCategory),
        new("blog:publish", "Publish blog posts", ManagementConstants.ContentManagementCategory),
        new("blog:unpublish", "Unpublish blog posts", ManagementConstants.ContentManagementCategory),
        
        // Comment Management
        new("comment:view", "View comments", ManagementConstants.ContentManagementCategory),
        new("comment:moderate", "Moderate comments", ManagementConstants.ContentManagementCategory),
        new("comment:delete", "Delete comments", ManagementConstants.ContentManagementCategory),
        
        // Category & Tag Management
        new("category:view", "View categories", ManagementConstants.ContentManagementCategory),
        new("category:create", "Create categories", ManagementConstants.ContentManagementCategory),
        new("category:update", "Update categories", ManagementConstants.ContentManagementCategory),
        
        new("tag:view", "View tags", ManagementConstants.ContentManagementCategory),
        new("tag:create", "Create tags", ManagementConstants.ContentManagementCategory),
        new("tag:update", "Update tags", ManagementConstants.ContentManagementCategory),
        
        // Limited User Management
        new("user:view", "View user details", ManagementConstants.UserManagementCategory)
    ];

    public static List<ManagementPermission> AnalystPermissions =>
    [
        // Read-only permissions
        new("system:view-analytics", "View analytics", ManagementConstants.SystemManagementCategory),
        new("user:view", "View user details", ManagementConstants.UserManagementCategory),
        new("content:view", "View content", ManagementConstants.ContentManagementCategory),
        new("blog:view", "View blog posts", ManagementConstants.ContentManagementCategory),
        new("comment:view", "View comments", ManagementConstants.ContentManagementCategory),
        new("category:view", "View categories", ManagementConstants.ContentManagementCategory),
        new("tag:view", "View tags", ManagementConstants.ContentManagementCategory)
    ];

    public static List<ManagementPermission> SupportPermissions =>
    [
        // Support specific permissions
        new("support:view-tickets", "View support tickets", ManagementConstants.SupportCategory),
        new("support:resolve-tickets", "Resolve support tickets", ManagementConstants.SupportCategory),
        new("support:manage-tickets", "Manage support tickets", ManagementConstants.SupportCategory),
        
        // Limited user view
        new("user:view", "View user details", ManagementConstants.UserManagementCategory)
    ];
} 