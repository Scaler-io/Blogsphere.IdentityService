using Duende.IdentityServer.Validation;
using IdentityService.Entities;
using IdentityService.Management.Entities;
using IdentityService.Management.Services;
using IdentityService.Management.Models;
using IdentityService.Extensions;
using Microsoft.AspNetCore.Identity;

namespace IdentityService.Services;

public class MultiUserResourceOwnerPasswordValidator(
    UserManager<ApplicationUser> applicationUserManager,
    UserManager<ManagementUser> managementUserManager,
    IMultiUserStoreService multiUserStoreService,
    ILogger logger) : IResourceOwnerPasswordValidator
{
    private readonly UserManager<ApplicationUser> _applicationUserManager = applicationUserManager;
    private readonly UserManager<ManagementUser> _managementUserManager = managementUserManager;
    private readonly IMultiUserStoreService _multiUserStoreService = multiUserStoreService;
    private readonly ILogger _logger = logger;

    public async Task ValidateAsync(ResourceOwnerPasswordValidationContext context)
    {
        try
        {
            var username = context.UserName;
            var password = context.Password;
            var clientId = context.Request?.Client?.ClientId;

            _logger.Here().Information("Validating credentials for username: {Username} with client: {ClientId}", username, clientId);

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                _logger.Here().Warning("Username or password is empty");
                context.Result = new GrantValidationResult(Duende.IdentityServer.Models.TokenRequestErrors.InvalidGrant, "invalid_username_or_password");
                return;
            }

            string userStore;
            bool isValid = true;

            // If client ID is present, validate both email and client ID
            if (!string.IsNullOrEmpty(clientId))
            {
                var (store, validationResult) = await _multiUserStoreService.DetermineUserStoreWithClientValidationAsync(username, clientId);
                userStore = store;
                isValid = validationResult;
                _logger.Here().Information("Determined user store {UserStore} for username {Username} with client {ClientId}, IsValid: {IsValid}", userStore, username, clientId, isValid);

                if (!isValid)
                {
                    _logger.Here().Warning("Client validation failed for username: {Username} with client: {ClientId}", username, clientId);
                    context.Result = new GrantValidationResult(Duende.IdentityServer.Models.TokenRequestErrors.InvalidGrant, "invalid_client_for_user_type");
                    return;
                }
            }
            else
            {
                // If no client ID, use email-based determination only
                userStore = await _multiUserStoreService.DetermineUserStoreByEmailAsync(username);
                _logger.Here().Information("No client ID provided, using email-based determination: {UserStore} for username {Username}", userStore, username);
            }

            if (userStore == ManagementConstants.ManagementUserStore)
            {
                await ValidateManagementUserAsync(context, username, password);
            }
            else
            {
                await ValidateApplicationUserAsync(context, username, password);
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error during password validation for username: {Username}", context.UserName);
            context.Result = new GrantValidationResult(Duende.IdentityServer.Models.TokenRequestErrors.InvalidGrant, "invalid_username_or_password");
        }
    }

    private async Task ValidateApplicationUserAsync(ResourceOwnerPasswordValidationContext context, string username, string password)
    {
        _logger.Here().Information("Attempting to validate ApplicationUser with username: {Username}", username);
        
        var user = await _applicationUserManager.FindByEmailAsync(username);
        if (user == null)
        {
            _logger.Here().Warning("ApplicationUser not found for username: {Username}", username);
            context.Result = new GrantValidationResult(Duende.IdentityServer.Models.TokenRequestErrors.InvalidGrant, "invalid_username_or_password");
            return;
        }

        _logger.Here().Information("ApplicationUser found: {UserId}, EmailConfirmed: {EmailConfirmed}", user.Id, user.EmailConfirmed);

        if (!user.EmailConfirmed)
        {
            _logger.Here().Warning("ApplicationUser email not confirmed for username: {Username}", username);
            context.Result = new GrantValidationResult(Duende.IdentityServer.Models.TokenRequestErrors.InvalidGrant, "email_not_confirmed");
            return;
        }

        var isValidPassword = await _applicationUserManager.CheckPasswordAsync(user, password);
        _logger.Here().Information("Password validation result for ApplicationUser {Username}: {IsValid}", username, isValidPassword);
        
        if (!isValidPassword)
        {
            _logger.Here().Warning("Invalid password for ApplicationUser: {Username}", username);
            context.Result = new GrantValidationResult(Duende.IdentityServer.Models.TokenRequestErrors.InvalidGrant, "invalid_username_or_password");
            return;
        }

        _logger.Here().Information("Successfully validated ApplicationUser: {Username}", username);

        var claims = new List<System.Security.Claims.Claim>
        {
            new(System.Security.Claims.ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(System.Security.Claims.ClaimTypes.Name, user.UserName ?? user.Email ?? username),
            new(System.Security.Claims.ClaimTypes.Email, user.Email ?? username),
            new("user_type", "application")
        };

        if (!string.IsNullOrEmpty(user.FirstName))
            claims.Add(new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.GivenName, user.FirstName));
        
        if (!string.IsNullOrEmpty(user.Lastname))
            claims.Add(new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Surname, user.Lastname));

        context.Result = new GrantValidationResult(user.Id.ToString(), "password", claims);
    }

    private async Task ValidateManagementUserAsync(ResourceOwnerPasswordValidationContext context, string username, string password)
    {
        _logger.Here().Information("Attempting to validate ManagementUser with username: {Username}", username);
        
        var user = await _managementUserManager.FindByEmailAsync(username);
        if (user == null)
        {
            _logger.Here().Warning("ManagementUser not found for username: {Username}", username);
            context.Result = new GrantValidationResult(Duende.IdentityServer.Models.TokenRequestErrors.InvalidGrant, "invalid_username_or_password");
            return;
        }

        _logger.Here().Information("ManagementUser found: {UserId}, EmailConfirmed: {EmailConfirmed}", user.Id, user.EmailConfirmed);

        if (!user.EmailConfirmed)
        {
            _logger.Here().Warning("ManagementUser email not confirmed for username: {Username}", username);
            context.Result = new GrantValidationResult(Duende.IdentityServer.Models.TokenRequestErrors.InvalidGrant, "email_not_confirmed");
            return;
        }

        var isValidPassword = await _managementUserManager.CheckPasswordAsync(user, password);
        _logger.Here().Information("Password validation result for ManagementUser {Username}: {IsValid}", username, isValidPassword);
        
        if (!isValidPassword)
        {
            _logger.Here().Warning("Invalid password for ManagementUser: {Username}", username);
            context.Result = new GrantValidationResult(Duende.IdentityServer.Models.TokenRequestErrors.InvalidGrant, "invalid_username_or_password");
            return;
        }

        _logger.Here().Information("Successfully validated ManagementUser: {Username}", username);

        var claims = new List<System.Security.Claims.Claim>
        {
            new(System.Security.Claims.ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(System.Security.Claims.ClaimTypes.Name, user.UserName ?? user.Email ?? username),
            new(System.Security.Claims.ClaimTypes.Email, user.Email ?? username),
            new("user_type", "management")
        };

        if (!string.IsNullOrEmpty(user.FirstName))
            claims.Add(new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.GivenName, user.FirstName));
        
        if (!string.IsNullOrEmpty(user.LastName))
            claims.Add(new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Surname, user.LastName));

        context.Result = new GrantValidationResult(user.Id.ToString(), "password", claims);
    }
} 