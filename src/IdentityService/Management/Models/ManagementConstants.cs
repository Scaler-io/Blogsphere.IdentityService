namespace IdentityService.Management.Models;

public static class ManagementConstants
{
    public static List<string> ManagementClientIds = ["blogsphere-management", "postman"];
    public const string ManagementClientName = "Blogsphere Management Application";
    public const string ManagementUserStore = "Management";
    public const string BlogsphereUserStore = "Blogsphere";
    
    // Management email domains
    public static readonly string[] ManagementEmailDomains =
    [
        "@blogsphere.management",
        "@blogsphere.internal", 
        "@blogsphere.admin"
    ];
    
    // Specific management email addresses
    public static readonly string[] ManagementEmailAddresses =
    [
        "admin@blogsphere.com",
        "superadmin@blogsphere.com",
        "manager@blogsphere.com",
        "moderator@blogsphere.com",
        "analyst@blogsphere.com",
        "support@blogsphere.com"
    ];
    
    // Default roles
    public const string SuperAdminRole = "SuperAdmin";
    public const string AdminRole = "Admin";
    public const string ManagerRole = "Manager";
    public const string ModeratorRole = "Moderator";
    public const string AnalystRole = "Analyst";
    public const string SupportRole = "Support";
    
    // Permission categories
    public const string UserManagementCategory = "User Management";
    public const string ContentManagementCategory = "Content Management";
    public const string SystemManagementCategory = "System Management";
    public const string RoleManagementCategory = "Role Management";
    public const string SupportCategory = "Support";
    
    // Default management user
    public const string DefaultManagementUserEmail = "admin@blogsphere.management";
    public const string DefaultManagementUserName = "admin";
    public const string DefaultManagementPassword = "Admin@123";
    
    // Token providers
    public const string ManagementEmailTokenProvider = "ManagementEmailTokenProvider";
    public const string ManagementPasswordResetTokenProvider = "ManagementPasswordResetTokenProvider";
    public const string ManagementTwoFactorTokenProvider = "ManagementTwoFactorTokenProvider";
} 