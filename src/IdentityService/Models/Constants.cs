using IdentityService.Entities;

namespace IdentityService.Models;

public class Constants
{
    public const string AppCorsPolicy = "BlogSpahereIdentityCors";
    public const string CustomEmailTokenProvider = "BlogsphereEmailTokenProvider";
    public const string CustomPasswordResetTokenProvider = "BlogspherePassResetTokenProvider";
    public const string CustomTwoFactorTokenProvider = "BlogsphereTwoFactorTokenProvider";
}

public class LoggerConstants
{
    public const string MethodEntered = "Entered.";
    public const string MethodExited = "Exited.";
    public const string OperationFailed = "Operation Failed.";
    public const string MemberName = "MemberName";
    public const string CallerType = "CallerType";
    public const string CorrelationId = "CorrelationId";
}

public static class RolePermissionMap
{
    public static List<ApplicationPermission> AdminPermissions =
    [
        // Blog Post Permissions
        new("post:create"),
        new("post:read"),        // View any post
        new("post:update"),      // Edit any post
        new("post:delete"),      // Delete any post
        new("post:publish"),     // Publish a post
        new("post:unpublish"),   // Unpublish a post

        // Comment Permissions
        new("comment:read"),     // View all comments
        new("comment:write"),
        new("comment:approve"),  // Approve comments
        new("comment:delete"),   // Delete comments

        // User Management Permissions
        new("user:create"),
        new("user:read"),        // View user details
        new("user:update"),      // Update user details (including roles)
        new("user:delete"),      // Delete users

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
        new("settings:read"),     // View settings
        new("settings:update")    // Update application settings
    ];

    public static List<ApplicationPermission> EditorPermissions = 
    [
        // Blog Post Permissions
        new("post:create"),         // Create new posts
        new("post:read"),           // View all posts
        new("post:update"),         // Edit any post
        new("post:delete"),         // Delete any post
        new("post:publish"),        // Publish a post                                                                                                                                                                                                         
        new("post:unpublish"),

        // Comment Moderation
        new("comment:approve"),     // Approve comments
        new("comment:delete"),      // Delete comments

        // Category Management
        new("category:create"),
        new("category:read"),
        new("category:update"),
        new("category:delete"),     

        // Tag Management
        new("tag:create"),
        new("tag:read"),
        new("tag:update"),
        new("tag:delete")
    ];

    public static List<ApplicationPermission> AuthorPermissions = 
    [
        // Own Blog Post Permissions
        new("post:create"),         // Create a new post
        new("post:read"),           // View own posts
        new("post:update"),         // Edit own unpublished posts        
        new("post:delete"),         // Delete own unpublished posts
    ];

    public static List<ApplicationPermission> SubscriberPermissions =
    [
        new("post:read"),
        new("comment:read"),
        new("comment:write")
    ];
}