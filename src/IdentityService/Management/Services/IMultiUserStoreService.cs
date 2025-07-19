using IdentityService.Management.Entities;
using Microsoft.AspNetCore.Identity;

namespace IdentityService.Management.Services;

public interface IMultiUserStoreService
{
    Task<string> DetermineUserStoreAsync(string clientId);
    Task<string> DetermineUserStoreByEmailAsync(string email);
    Task<(string UserStore, bool IsValid)> DetermineUserStoreWithClientValidationAsync(string email, string clientId);
    Task<string> GetUserStoreFromReturnUrlAsync(string returnUrl);
    Task<ManagementUser> GetManagementUserAsync(string username);
    Task<ManagementUser> GetManagementUserByEmailAsync(string email);
    Task<string> GenerateManagementPasswordResetTokenAsync(ManagementUser user);
    Task<IdentityResult> ResetManagementPasswordAsync(ManagementUser user, string token, string newPassword);
    Task<string> GenerateManagementEmailConfirmationTokenAsync(ManagementUser user);
    Task<IdentityResult> ConfirmManagementEmailAsync(ManagementUser user, string token);
    Task<string> GenerateManagementTwoFactorTokenAsync(ManagementUser user);
    Task<bool> VerifyManagementTwoFactorTokenAsync(ManagementUser user, string token);
    Task SetManagementAuthenticationTokenAsync(ManagementUser user, string loginProvider, string name, string value);
    Task RemoveManagementAuthenticationTokenAsync(ManagementUser user, string loginProvider, string name);
    Task<string> GetManagementAuthenticationTokenAsync(ManagementUser user, string loginProvider, string name);
}