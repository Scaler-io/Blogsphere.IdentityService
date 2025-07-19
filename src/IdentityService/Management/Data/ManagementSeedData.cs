using IdentityService.Management.Entities;
using IdentityService.Management.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using IdentityModel;
using IdentityService.Management.Models.Enums;
using IdentityService.Models;

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
        
        // Begin transaction for consistency
        using var transaction = await context.Database.BeginTransactionAsync();
        
        try
        {
            // Seed permissions first
            await SeedPermissionsAsync(context, logger);
            
            // Seed roles
            await SeedRolesAsync(roleManager, logger);
            
            // Seed role-permission relationships
            await SeedRolePermissionsAsync(context, roleManager, logger);
            
            // Seed users
            await SeedUsersAsync(userManager, roleManager, logger);
            
            // Commit transaction
            await transaction.CommitAsync();
            logger.Information("Management data seeding completed successfully");
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync();
            logger.Error(ex, "Failed to seed management data");
            throw;
        }
    }

    private static async Task SeedPermissionsAsync(ManagementDbContext context, ILogger logger)
    {
        logger.Information("Seeding management permissions");
        
        if (await context.ManagementPermissions.AnyAsync())
        {
            logger.Information("Management permissions already exist, skipping seeding");
            return;
        }

        var allPermissions = GetAllPermissions();
        
        foreach (var permission in allPermissions)
        {
            permission.SetAsSystemPermission();
            context.ManagementPermissions.Add(permission);
        }
        
        await context.SaveChangesAsync();
        logger.Information("Seeded {Count} management permissions", allPermissions.Count);
    }

    private static async Task SeedRolePermissionsAsync(ManagementDbContext context, RoleManager<ManagementRole> roleManager, ILogger logger)
    {
        logger.Information("Seeding management role-permission relationships");
        
        if (await context.ManagementRolePermissions.AnyAsync())
        {
            logger.Information("Management role-permission relationships already exist, skipping seeding");
            return;
        }

        var existingPermissions = await context.ManagementPermissions.ToListAsync();
        var existingRoles = await roleManager.Roles.ToListAsync();
        
        var rolePermissionAssignments = new[]
        {
            new { RoleName = nameof(ManagementRoles.SuperAdmin), Permissions = ManagementRolePermissionMap.AdminPermissions },
            new { RoleName = nameof(ManagementRoles.Admin), Permissions = ManagementRolePermissionMap.AdminPermissions },
            new { RoleName = nameof(ManagementRoles.Manager), Permissions = ManagementRolePermissionMap.ManagerPermissions },
            new { RoleName = nameof(ManagementRoles.Moderator), Permissions = ManagementRolePermissionMap.ModeratorPermissions },
            new { RoleName = nameof(ManagementRoles.Analyst), Permissions = ManagementRolePermissionMap.AnalystPermissions },
            new { RoleName = nameof(ManagementRoles.Support), Permissions = ManagementRolePermissionMap.SupportPermissions }
        };

        foreach (var assignment in rolePermissionAssignments)
        {
            var role = existingRoles.FirstOrDefault(r => r.Name == assignment.RoleName);
            if (role == null)
            {
                logger.Warning("Role {RoleName} not found, skipping permission assignment", assignment.RoleName);
                continue;
            }

            foreach (var permissionTemplate in assignment.Permissions)
            {
                var permission = existingPermissions.FirstOrDefault(p => p.Name == permissionTemplate.Name);
                if (permission != null)
                {
                    var rolePermission = new ManagementRolePermission
                    {
                        RoleId = role.Id,
                        PermissionId = permission.Id,
                        AssignedAt = DateTime.UtcNow,
                        AssignedBy = "System"
                    };
                    
                    context.ManagementRolePermissions.Add(rolePermission);
                }
                else
                {
                    logger.Warning("Permission {PermissionName} not found for role {RoleName}", permissionTemplate.Name, assignment.RoleName);
                }
            }
            
            logger.Information("Assigned {Count} permissions to role {RoleName}", assignment.Permissions.Count, assignment.RoleName);
        }
        
        await context.SaveChangesAsync();
        logger.Information("Management role-permission relationships seeding completed");
    }

    private static async Task SeedRolesAsync(RoleManager<ManagementRole> roleManager, ILogger logger)
    {
        logger.Information("Seeding management roles");
        
        var roles = new[]
        {
            new ManagementRole { Name = nameof(ManagementRoles.SuperAdmin), Description = "Super Administrator with full access" },
            new ManagementRole { Name = nameof(ManagementRoles.Admin), Description = "Administrator with limited access" },
            new ManagementRole { Name = nameof(ManagementRoles.Manager), Description = "Manager with content and user management access" },
            new ManagementRole { Name = nameof(ManagementRoles.Moderator), Description = "Moderator with content management access" },
            new ManagementRole { Name = nameof(ManagementRoles.Analyst), Description = "Analyst with read-only access to analytics and data" },
            new ManagementRole { Name = nameof(ManagementRoles.Support), Description = "Support staff with user assistance access" }
        };

        foreach (var role in roles)
        {
            if (!await roleManager.RoleExistsAsync(role.Name))
            {
                role.SetAsSystemRole();
                await roleManager.CreateAsync(role);
                logger.Information("Created management role: {RoleName}", role.Name);
            }
        }
    }

    private static async Task SeedUsersAsync(UserManager<ManagementUser> userManager, RoleManager<ManagementRole> roleManager, ILogger logger)
    {
        logger.Information("Seeding management users");
        
        var users = new[]
        {
            new ManagementUser("Super", "Admin", "superadmin@blogsphere.com", "IT") { JobTitle = "System Administrator", EmployeeId = IdGenerator.NewManagementUserId("IT", "ADM") },
            new ManagementUser("Admin", "User", "admin@blogsphere.com", "IT") { JobTitle = "Administrator", EmployeeId = IdGenerator.NewManagementUserId("IT", "ADM") }
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
                    
                    // Assign roles based on email
                    var role = user.Email == "superadmin@blogsphere.com" ? nameof(ManagementRoles.SuperAdmin) : nameof(ManagementRoles.Admin);
                    if (await roleManager.RoleExistsAsync(role))
                    {
                        await userManager.AddToRoleAsync(user, role);
                        logger.Information("Assigned role {Role} to management user: {Email}", role, user.Email);
                    }
                    
                    // Add standard claims to the user
                    await AddClaims(user, userManager, role, logger);
                    
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

    private static async Task AddClaims(ManagementUser user, UserManager<ManagementUser> userManager, string role, ILogger logger)
    {
        try
        {
            var claims = new List<Claim>
            {
                new(JwtClaimTypes.Name, user.FullName),
                new(JwtClaimTypes.GivenName, user.FirstName),
                new(JwtClaimTypes.FamilyName, user.LastName),
                new(JwtClaimTypes.Email, user.Email ?? string.Empty),
                new(JwtClaimTypes.Role, role),
                new("employee_id", user.EmployeeId ?? string.Empty),
                new("department", user.Department ?? string.Empty),
                new("job_title", user.JobTitle ?? string.Empty)
            };

            await userManager.AddClaimsAsync(user, claims);
            logger.Information("Added standard claims to management user: {Email}", user.Email);
        }
        catch (Exception ex)
        {
            logger.Error(ex, "Failed to add claims to management user: {Email}", user.Email);
        }
    }

    private static List<ManagementPermission> GetAllPermissions()
    {
        // Combine all permissions from different role mappings and remove duplicates
        var allPermissions = new List<ManagementPermission>();
        
        // Add all unique permissions from different role permission sets
        var permissionSets = new[]
        {
            ManagementRolePermissionMap.AdminPermissions,
            ManagementRolePermissionMap.ManagerPermissions,
            ManagementRolePermissionMap.ModeratorPermissions,
            ManagementRolePermissionMap.AnalystPermissions,
            ManagementRolePermissionMap.SupportPermissions
        };

        var uniquePermissions = new HashSet<string>();
        
        foreach (var permissionSet in permissionSets)
        {
            foreach (var permission in permissionSet)
            {
                if (uniquePermissions.Add(permission.Name))
                {
                    allPermissions.Add(new ManagementPermission(permission.Name, permission.Description, permission.Category));
                }
            }
        }
        
        return allPermissions;
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
        new("system:view-settings", "View system settings", ManagementConstants.SystemManagementCategory),
        new("system:update-settings", "Update system settings", ManagementConstants.SystemManagementCategory),
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