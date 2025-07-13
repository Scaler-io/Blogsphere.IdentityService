namespace IdentityService.Management.Models.Enums;

public enum ManagementPermissions
{
    // User Management
    ViewUsers,
    CreateUsers,
    EditUsers,
    DeleteUsers,
    ManageUserRoles,
    
    // Content Management
    ViewContent,
    CreateContent,
    EditContent,
    DeleteContent,
    ModerateContent,
    
    // System Management
    ViewSystemLogs,
    ManageSystemSettings,
    ViewAnalytics,
    ManageBackups,
    
    // Role Management
    ViewRoles,
    CreateRoles,
    EditRoles,
    DeleteRoles,
    AssignPermissions,
    
    // Support
    ViewSupportTickets,
    ResolveSupportTickets,
    ManageSupportTickets
} 