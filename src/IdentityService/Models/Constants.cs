using IdentityService.Entities;
using IdentityService.Management.Models.Enums;

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

/// <summary>
/// Utility class for generating uniform IDs across all user types and entities
/// </summary>
public static class IdGenerator
{
    public const int MaxManagementEmployeeIdLength = 20;

    private static readonly Dictionary<string, string> ManagementRoleAbbreviations = new(StringComparer.OrdinalIgnoreCase)
    {
        [nameof(ManagementRoles.SuperAdmin)] = "SAD",
        [nameof(ManagementRoles.Admin)] = "ADM",
        [nameof(ManagementRoles.Manager)] = "MGR",
        [nameof(ManagementRoles.Moderator)] = "MOD",
        [nameof(ManagementRoles.Analyst)] = "ANL",
        [nameof(ManagementRoles.Support)] = "SUP",
        [nameof(ManagementRoles.SystemAdmin)] = "SYS",
    };

    private static readonly HashSet<string> KnownRoleAbbreviations = new(StringComparer.OrdinalIgnoreCase)
    {
        "SAD", "ADM", "MGR", "MOD", "ANL", "SUP", "SYS"
    };

    /// <summary>
    /// Generates a new GUID-based ID for any entity
    /// </summary>
    /// <returns>A new GUID string</returns>
    public static string NewId() => Guid.NewGuid().ToString();

    /// <summary>
    /// Generates a new ID with a specific prefix for better identification
    /// </summary>
    /// <param name="prefix">Prefix to add to the ID (e.g., "USER", "ROLE", "PERM")</param>
    /// <returns>A prefixed GUID string</returns>
    public static string NewId(string prefix) => $"{prefix}_{Guid.NewGuid():N}";

    /// <summary>
    /// Generates a short ID for entities that don't need full GUID length
    /// </summary>
    /// <returns>A short 8-character ID</returns>
    public static string NewShortId() => Guid.NewGuid().ToString("N")[..8].ToUpper();

    /// <summary>
    /// Normalizes a department code for employee ID generation.
    /// </summary>
    public static string NormalizeDepartment(string department)
    {
        if (string.IsNullOrWhiteSpace(department))
            throw new ArgumentException("Department is required.", nameof(department));

        return department.Trim().ToUpperInvariant();
    }

    /// <summary>
    /// Resolves a management role name or abbreviation to a 3-letter employee ID code.
    /// </summary>
    public static string ResolveRoleAbbreviation(string role)
    {
        if (string.IsNullOrWhiteSpace(role))
            throw new ArgumentException("Role is required.", nameof(role));

        var trimmed = role.Trim();

        if (ManagementRoleAbbreviations.TryGetValue(trimmed, out var mappedAbbreviation))
            return mappedAbbreviation;

        var upper = trimmed.ToUpperInvariant();
        if (KnownRoleAbbreviations.Contains(upper))
            return upper;

        if (upper.Length == 3 && upper.All(char.IsLetter))
            return upper;

        var letters = trimmed.Where(char.IsLetter).Take(3).Select(char.ToUpperInvariant).ToArray();
        return letters.Length >= 3
            ? new string(letters, 0, 3)
            : new string(letters).PadRight(3, 'X');
    }

    /// <summary>
    /// Generates a user-friendly ID for management users.
    /// </summary>
    /// <param name="department">Department code (e.g., "IT", "OPS")</param>
    /// <param name="role">Management role name or abbreviation (e.g., "Manager", "MGR")</param>
    /// <returns>A formatted employee ID: {DEPT}{ROLE_ABBR}{yyMMdd}{4chars}</returns>
    public static string NewManagementUserId(string department, string role)
    {
        var dept = NormalizeDepartment(department);
        var roleAbbr = ResolveRoleAbbreviation(role);
        var suffix = NewShortId()[..4];
        var id = $"{dept}{roleAbbr}{DateTime.UtcNow:yyMMdd}{suffix}";

        if (id.Length > MaxManagementEmployeeIdLength)
        {
            throw new InvalidOperationException(
                $"Employee ID '{id}' exceeds {MaxManagementEmployeeIdLength} characters. Use shorter department/role codes.");
        }

        return id;
    }
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