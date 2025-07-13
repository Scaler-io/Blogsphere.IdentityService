using Duende.IdentityServer.Services;
using IdentityService.Management.Entities;
using IdentityService.Management.Models;
using IdentityService.Extensions;
using Microsoft.AspNetCore.Identity;

namespace IdentityService.Management.Services;

public class MultiUserStoreService(
    UserManager<ManagementUser> managementUserManager,
    IIdentityServerInteractionService interaction,
    ILogger logger) : IMultiUserStoreService
{

    private readonly UserManager<ManagementUser> _managementUserManager = managementUserManager;
    private readonly IIdentityServerInteractionService _interaction = interaction;
    private readonly ILogger _logger = logger;

    public Task<string> DetermineUserStoreAsync(string clientId)
    {
        if (string.IsNullOrEmpty(clientId))
        {
            return Task.FromResult(ManagementConstants.BlogsphereUserStore);
        }

        var result = ManagementConstants.ManagementClientIds.Contains(clientId) 
            ? ManagementConstants.ManagementUserStore 
            : ManagementConstants.BlogsphereUserStore;
            
        return Task.FromResult(result);
    }

    public Task<string> DetermineUserStoreByEmailAsync(string email)
    {
        if (string.IsNullOrEmpty(email))
        {
            return Task.FromResult(ManagementConstants.BlogsphereUserStore);
        }

        _logger.Here().Information("Determining user store for email: {Email}", email);

        // Check if email matches management user patterns
        if (IsManagementEmail(email))
        {
            _logger.Here().Information("Email {Email} identified as management user", email);
            return Task.FromResult(ManagementConstants.ManagementUserStore);
        }

        _logger.Here().Information("Email {Email} identified as blogsphere user", email);
        return Task.FromResult(ManagementConstants.BlogsphereUserStore);
    }

    public async Task<(string UserStore, bool IsValid)> DetermineUserStoreWithClientValidationAsync(string email, string clientId)
    {
        if (string.IsNullOrEmpty(email))
        {
            _logger.Here().Warning("Email is null or empty");
            return (ManagementConstants.BlogsphereUserStore, false);
        }

        if (string.IsNullOrEmpty(clientId))
        {
            _logger.Here().Warning("Client ID is null or empty");
            return (ManagementConstants.BlogsphereUserStore, false);
        }

        _logger.Here().Information("Determining user store for email: {Email} with client ID: {ClientId}", email, clientId);

        // Determine user store based on email
        var emailBasedUserStore = await DetermineUserStoreByEmailAsync(email);
        
        // Determine user store based on client ID
        var clientBasedUserStore = await DetermineUserStoreAsync(clientId);

        _logger.Here().Information("Email-based user store: {EmailStore}, Client-based user store: {ClientStore}", 
            emailBasedUserStore, clientBasedUserStore);

        // Check if the user store determined by email matches the client ID
        var isValid = emailBasedUserStore == clientBasedUserStore;

        if (!isValid)
        {
            _logger.Here().Warning("User store mismatch: Email '{Email}' suggests {EmailStore} but client '{ClientId}' suggests {ClientStore}", 
                email, emailBasedUserStore, clientId, clientBasedUserStore);
        }
        else
        {
            _logger.Here().Information("User store validation successful: {UserStore} for email '{Email}' and client '{ClientId}'", 
                emailBasedUserStore, email, clientId);
        }

        return (emailBasedUserStore, isValid);
    }

    private bool IsManagementEmail(string email)
    {
        if (string.IsNullOrEmpty(email))
        {
            _logger.Here().Information("Email is null or empty, returning false");
            return false;
        }

        var emailLower = email.ToLowerInvariant();
        _logger.Here().Information("Checking email: {Email} (normalized: {EmailLower})", email, emailLower);
        
        // Check if email ends with any management domain
        foreach (var domain in ManagementConstants.ManagementEmailDomains)
        {
            if (emailLower.EndsWith(domain))
            {
                _logger.Here().Information("Email {Email} matches management domain {Domain}", email, domain);
                return true;
            }
        }

        // Check for specific management email patterns
        if (ManagementConstants.ManagementEmailAddresses.Contains(emailLower))
        {
            _logger.Here().Information("Email {Email} found in management email addresses list", email);
            return true;
        }

        _logger.Here().Information("Email {Email} is NOT a management email", email);
        return false;
    }

    public async Task<string> GetUserStoreFromReturnUrlAsync(string returnUrl)
    {
        if (string.IsNullOrEmpty(returnUrl))
        {
            return ManagementConstants.BlogsphereUserStore;
        }

        try
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.Client?.ClientId != null)
            {
                return await DetermineUserStoreAsync(context.Client.ClientId);
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error determining user store from return URL: {ReturnUrl}", returnUrl);
        }

        return ManagementConstants.BlogsphereUserStore;
    }

    // Management user operations
    public async Task<ManagementUser> GetManagementUserAsync(string username)
    {
        return await _managementUserManager.FindByNameAsync(username);
    }

    public async Task<ManagementUser> GetManagementUserByEmailAsync(string email)
    {
        return await _managementUserManager.FindByEmailAsync(email);
    }

    public async Task<string> GenerateManagementPasswordResetTokenAsync(ManagementUser user)
    {
        _logger.Here().Information("Generating password reset token for management user {UserId}", user.Id);
        return await _managementUserManager.GeneratePasswordResetTokenAsync(user);
    }

    public async Task<IdentityResult> ResetManagementPasswordAsync(ManagementUser user, string token, string newPassword)
    {
        _logger.Here().Information("Resetting password for management user {UserId}", user.Id);
        return await _managementUserManager.ResetPasswordAsync(user, token, newPassword);
    }

    public async Task<string> GenerateManagementEmailConfirmationTokenAsync(ManagementUser user)
    {
        _logger.Here().Information("Generating email confirmation token for management user {UserId}", user.Id);
        return await _managementUserManager.GenerateEmailConfirmationTokenAsync(user);
    }

    public async Task<IdentityResult> ConfirmManagementEmailAsync(ManagementUser user, string token)
    {
        _logger.Here().Information("Confirming email for management user {UserId}", user.Id);
        return await _managementUserManager.ConfirmEmailAsync(user, token);
    }

    public async Task<string> GenerateManagementTwoFactorTokenAsync(ManagementUser user)
    {
        _logger.Here().Information("Generating 2FA token for management user {UserId}", user.Id);
        return await _managementUserManager.GenerateTwoFactorTokenAsync(user, ManagementConstants.ManagementTwoFactorTokenProvider);
    }

    public async Task<bool> VerifyManagementTwoFactorTokenAsync(ManagementUser user, string token)
    {
        _logger.Here().Information("Verifying 2FA token for management user {UserId}", user.Id);
        return await _managementUserManager.VerifyTwoFactorTokenAsync(user, ManagementConstants.ManagementTwoFactorTokenProvider, token);
    }

    public async Task SetManagementAuthenticationTokenAsync(ManagementUser user, string loginProvider, string name, string value)
    {
        await _managementUserManager.SetAuthenticationTokenAsync(user, loginProvider, name, value);
    }

    public async Task RemoveManagementAuthenticationTokenAsync(ManagementUser user, string loginProvider, string name)
    {
        await _managementUserManager.RemoveAuthenticationTokenAsync(user, loginProvider, name);
    }

    public async Task<string> GetManagementAuthenticationTokenAsync(ManagementUser user, string loginProvider, string name)
    {
        return await _managementUserManager.GetAuthenticationTokenAsync(user, loginProvider, name);
    }
} 