using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using IdentityModel;
using IdentityService.Entities;
using IdentityService.Extensions;
using IdentityService.Management.Entities;
using IdentityService.Management.Models;
using IdentityService.Management.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using System.Security.Claims;

namespace IdentityService.Services;

public class UserProfileService(
    UserManager<ApplicationUser> applicationUserManager,
    UserManager<ManagementUser> managementUserManager,
    RoleManager<ApplicationRole> applicationRoleManager,
    RoleManager<ManagementRole> managementRoleManager,
    IMultiUserStoreService multiUserStoreService,
    ILogger logger) : IProfileService
{
    private readonly UserManager<ApplicationUser> _applicationUserManager = applicationUserManager;
    private readonly UserManager<ManagementUser> _managementUserManager = managementUserManager;
    private readonly RoleManager<ApplicationRole> _applicationRoleManager = applicationRoleManager;
    private readonly RoleManager<ManagementRole> _managementRoleManager = managementRoleManager;
    private readonly IMultiUserStoreService _multiUserStoreService = multiUserStoreService;
    private readonly ILogger _logger = logger;

    public async Task GetProfileDataAsync(ProfileDataRequestContext context)
    {
        try
        {
            var subjectId = context.Subject.GetSubjectId();
            _logger.Here().Information("Getting profile data for subject ID: {SubjectId}", subjectId);

            if (string.IsNullOrEmpty(subjectId))
            {
                _logger.Here().Warning("Subject ID is null or empty");
                return;
            }

            
            var managementUser = await _managementUserManager.FindByIdAsync(subjectId);
            if (managementUser != null)
            {
                _logger.Here().Information("Found ManagementUser {UserId} for profile data", managementUser.Id);
                await GetManagementUserProfileDataAsync(context, managementUser);
                return;
            }

            var applicationUser = await _applicationUserManager.FindByIdAsync(subjectId);
            if (applicationUser != null)
            {
                _logger.Here().Information("Found ApplicationUser {UserId} for profile data", applicationUser.Id);
                await GetApplicationUserProfileDataAsync(context, applicationUser);
                return;
            }

            var email = context.Subject.FindFirst(ClaimTypes.Email)?.Value;
            if (!string.IsNullOrEmpty(email))
            {
                _logger.Here().Information("Falling back to email-based lookup for profile data: {Email}", email);
                
                var userStore = await _multiUserStoreService.DetermineUserStoreByEmailAsync(email);
                _logger.Here().Information("Determined user store {UserStore} for email {Email}", userStore, email);

                if (userStore == ManagementConstants.ManagementUserStore)
                {
                    managementUser = await _managementUserManager.FindByEmailAsync(email);
                    if (managementUser != null)
                    {
                        await GetManagementUserProfileDataAsync(context, managementUser);
                        return;
                    }
                }
                else
                {
                    applicationUser = await _applicationUserManager.FindByEmailAsync(email);
                    if (applicationUser != null)
                    {
                        await GetApplicationUserProfileDataAsync(context, applicationUser);
                        return;
                    }
                }
            }

            _logger.Here().Warning("User not found for subject ID: {SubjectId}, email: {Email}", subjectId, email ?? "null");
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error getting profile data for subject: {SubjectId}", context.Subject.GetSubjectId());
        }
    }

    private async Task GetApplicationUserProfileDataAsync(ProfileDataRequestContext context, ApplicationUser user)
    {
        if (user == null)
        {
            _logger.Here().Warning("ApplicationUser is null");
            return;
        }

        var roles = await _applicationUserManager.GetRolesAsync(user);
        var permissions = await _applicationRoleManager.Roles
            .Where(r => roles.Contains(r.Name))
            .SelectMany(r => r.RolePermissions)
            .Select(rp => rp.Permission.Name)
            .Distinct()
            .ToListAsync();

        var existingClaims = await _applicationUserManager.GetClaimsAsync(user);

        var claims = new List<Claim>
        {
            new("sub", user.Id),
            new("user_type", "application"),
            new("roles", JsonConvert.SerializeObject(roles)),
            new("permissions", JsonConvert.SerializeObject(permissions))
        };

        if (existingClaims != null)
        {
            foreach (var existingClaim in existingClaims)
            {
                if (!claims.Any(c => c.Type == existingClaim.Type))
                {
                    claims.Add(existingClaim);
                }
            }
        }

        context.IssuedClaims.AddRange(claims);
    }

    private async Task GetManagementUserProfileDataAsync(ProfileDataRequestContext context, ManagementUser user)
    {
        if (user == null)
        {
            _logger.Here().Warning("ManagementUser is null");
            return;
        }

        var userRoles = await _managementUserManager.GetRolesAsync(user);
        
        var permissions = await _managementRoleManager.Roles
            .Where(r => userRoles.Contains(r.Name))
            .SelectMany(r => r.RolePermissions)
            .Select(rp => rp.Permission.Name)
            .Distinct()
            .ToListAsync();

        var existingClaims = await _managementUserManager.GetClaimsAsync(user);

        var isSuperAdmin = userRoles.Contains(ManagementConstants.SuperAdminRole);
        var isAdmin = userRoles.Contains(ManagementConstants.AdminRole);
        var claims = new List<Claim>
        {
            new("sub", user.Id),
            new("user_type", "management"),
            new("permissions", isSuperAdmin || isAdmin ? "*" :JsonConvert.SerializeObject(permissions)),
        };

        if (existingClaims != null)
        {
            foreach (var existingClaim in existingClaims)
            {
                if (!claims.Any(c => c.Type == existingClaim.Type))
                {
                    claims.Add(existingClaim);
                }
            }
        }

        context.IssuedClaims.AddRange(claims);
    }

    public async Task IsActiveAsync(IsActiveContext context)
    {
        try
        {
            var subjectId = context.Subject.GetSubjectId();
            _logger.Here().Information("Checking if user is active for subject ID: {SubjectId}", subjectId);

            if (string.IsNullOrEmpty(subjectId))
            {
                _logger.Here().Warning("Subject ID is null or empty");
                context.IsActive = false;
                return;
            }

            var managementUser = await _managementUserManager.FindByIdAsync(subjectId);
            if (managementUser != null)
            {
                _logger.Here().Information("Found ManagementUser {UserId}, IsActive: {IsActive}", managementUser.Id, managementUser.IsActive);
                context.IsActive = managementUser.IsActive;
                return;
            }

            var applicationUser = await _applicationUserManager.FindByIdAsync(subjectId);
            if (applicationUser != null)
            {
                _logger.Here().Information("Found ApplicationUser {UserId}, setting as active", applicationUser.Id);
                context.IsActive = true;
                return;
            }

            var email = context.Subject.FindFirst(ClaimTypes.Email)?.Value ?? 
                       context.Subject.FindFirst(JwtClaimTypes.Email)?.Value;
            
            if (!string.IsNullOrEmpty(email))
            {
                _logger.Here().Information("Falling back to email-based lookup for: {Email}", email);

                var userStore = await _multiUserStoreService.DetermineUserStoreByEmailAsync(email);
                _logger.Here().Information("Determined user store: {UserStore} for email: {Email}", userStore, email);

                if (userStore == ManagementConstants.ManagementUserStore)
                {
                    managementUser = await _managementUserManager.FindByEmailAsync(email);
                    if (managementUser != null)
                    {
                        _logger.Here().Information("Found ManagementUser by email {Email}, IsActive: {IsActive}", email, managementUser.IsActive);
                        context.IsActive = managementUser.IsActive;
                        return;
                    }
                }
                else
                {
                    applicationUser = await _applicationUserManager.FindByEmailAsync(email);
                    if (applicationUser != null)
                    {
                        _logger.Here().Information("Found ApplicationUser by email {Email}, setting as active", email);
                        context.IsActive = true;
                        return;
                    }
                }
            }

            _logger.Here().Warning("User not found for subject ID: {SubjectId}, email: {Email}", subjectId, email ?? "null");
            context.IsActive = false;
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error checking if user is active for subject: {SubjectId}", context.Subject.GetSubjectId());
            context.IsActive = false;
        }
    }
}
