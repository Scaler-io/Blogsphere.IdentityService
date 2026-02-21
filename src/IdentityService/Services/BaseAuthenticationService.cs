using Contracts.Events;
using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using IdentityService.Extensions;
using Microsoft.AspNetCore.Identity;
using Telemetry = IdentityService.Pages.Telemetry;


namespace IdentityService.Services;

public interface IBaseAuthenticationService<TUser> where TUser : IdentityUser
{
    Task<BlogsphereAuthenticationResult> AuthenticateAsync(string username, string password, bool rememberLogin, AuthorizationRequest context);
    Task<BlogsphereAuthenticationResult> ValidateTwoFactorTokenAsync(string email, string code, bool rememberLogin, AuthorizationRequest context);
    Task<TokenValidationResult> ValidatePasswordResetTokenAsync(string email, string token);
    Task<PasswordResetResult> ResetPasswordAsync(string email, string token, string newPassword);
    Task<TokenGenerationResult> GeneratePasswordResetTokenAsync(string email);
}

public class BaseAuthenticationService<TUser>(
    UserManager<TUser> userManager,
    SignInManager<TUser> signInManager,
    IEventService events,
    IPublishService publishService,
    ILogger logger,
    string userType,
    string twoFactorTokenProvider,
    string passwordResetTokenProvider) : IBaseAuthenticationService<TUser> where TUser : IdentityUser
{
    protected readonly UserManager<TUser> _userManager = userManager;
    protected readonly SignInManager<TUser> _signInManager = signInManager;
    protected readonly IEventService _events = events;
    protected readonly IPublishService _publishService = publishService;
    protected readonly ILogger _logger = logger;
    protected readonly string _userType = userType;
    protected readonly string _twoFactorTokenProvider = twoFactorTokenProvider;
    protected readonly string _passwordResetTokenProvider = passwordResetTokenProvider;

    public virtual async Task<BlogsphereAuthenticationResult> AuthenticateAsync(string username, string password, bool rememberLogin, AuthorizationRequest context)
    {
        var user = await _userManager.FindByNameAsync(username);
        if (user == null)
        {
            await _events.RaiseAsync(new UserLoginFailureEvent(username, "invalid credentials", clientId: context?.Client.ClientId));
            Telemetry.Metrics.UserLoginFailure(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider, "invalid credentials");
            return BlogsphereAuthenticationResult.Failed("Invalid credentials");
        }

        var result = await _signInManager.PasswordSignInAsync(user, password, rememberLogin, lockoutOnFailure: false);
        
        if (result.Succeeded)
        {
            await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, GetUserDisplayName(user), clientId: context?.Client.ClientId));
            Telemetry.Metrics.UserLogin(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider);

            return BlogsphereAuthenticationResult.Success();
        }
        else if (result.RequiresTwoFactor)
        {
            await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, GetUserDisplayName(user), clientId: context?.Client.ClientId));
            Telemetry.Metrics.UserLogin(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider);

            var code = await _userManager.GenerateTwoFactorTokenAsync(user, _twoFactorTokenProvider);
            
            await _userManager.SetAuthenticationTokenAsync(user, "2Fa", "2FACode", code);
            await _userManager.SetAuthenticationTokenAsync(user, "2Fa", "2FACodeExpiry", DateTime.UtcNow.AddMinutes(5).ToString());
            
            _logger.Here().Information("Sending 2FA code to {UserType} user", _userType);
            await _publishService.PublishAsync(new AuthCodeSent
            {
                Email = user.Email,
                Code = code                   
            }, Guid.NewGuid().ToString());
            
            return BlogsphereAuthenticationResult.CreateRequiresTwoFactor(user.Email, _userType);
        }
        else if (result.IsLockedOut)
        {
            return BlogsphereAuthenticationResult.LockedOut();
        }
        else
        {
            await _events.RaiseAsync(new UserLoginFailureEvent(username, "invalid credentials", clientId: context?.Client.ClientId));
            Telemetry.Metrics.UserLoginFailure(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider, "invalid credentials");
            return BlogsphereAuthenticationResult.Failed("Invalid credentials");
        }
    }

    public virtual async Task<BlogsphereAuthenticationResult> ValidateTwoFactorTokenAsync(string email, string code, bool rememberLogin, AuthorizationRequest context)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return BlogsphereAuthenticationResult.Failed("Invalid user");
        }

        var result = await _userManager.VerifyTwoFactorTokenAsync(user, _twoFactorTokenProvider, code);
        if (!result)
        {
            return BlogsphereAuthenticationResult.Failed("Invalid code");
        }

        await _signInManager.SignInAsync(user, rememberLogin);
        await _userManager.RemoveAuthenticationTokenAsync(user, "2Fa", "2FACode");
        await _userManager.RemoveAuthenticationTokenAsync(user, "2Fa", "2FACodeExpiry");

        await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, GetUserDisplayName(user), clientId: context?.Client.ClientId));
        Telemetry.Metrics.UserLogin(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider);

        return BlogsphereAuthenticationResult.Success();
    }

    public virtual async Task<TokenValidationResult> ValidatePasswordResetTokenAsync(string email, string token)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return TokenValidationResult.Invalid();
        }

        var result = await _userManager.VerifyUserTokenAsync(
            user, 
            _passwordResetTokenProvider, 
            UserManager<TUser>.ResetPasswordTokenPurpose, 
            token);

        return result ? TokenValidationResult.Valid() : TokenValidationResult.Invalid();
    }

    public virtual async Task<PasswordResetResult> ResetPasswordAsync(string email, string token, string newPassword)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return PasswordResetResult.Failed("User not found");
        }

        // Verify token explicitly with the specific token provider
        var tokenValid = await _userManager.VerifyUserTokenAsync(
            user, 
            _passwordResetTokenProvider, 
            UserManager<TUser>.ResetPasswordTokenPurpose, 
            token);
        
        if (!tokenValid)
        {
            return PasswordResetResult.Failed("Invalid or expired reset token");
        }

        // Remove password and set new one
        await _userManager.RemovePasswordAsync(user);
        var result = await _userManager.AddPasswordAsync(user, newPassword);
        
        if (result.Succeeded)
        {
            _logger.Here().Information("Password reset successful for {UserType} user {Email}", _userType, email);
            return PasswordResetResult.Success();
        }

        return PasswordResetResult.Failed(string.Join(", ", result.Errors.Select(e => e.Description)));
    }

    public virtual async Task<TokenGenerationResult> GeneratePasswordResetTokenAsync(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        
        if (user != null && await _userManager.IsEmailConfirmedAsync(user))
        {
            // Check if user is locked out
            if (!await _userManager.IsLockedOutAsync(user))
            {
                // Generate password reset token using the specific token provider
                var code = await _userManager.GenerateUserTokenAsync(
                    user, 
                    _passwordResetTokenProvider, 
                    UserManager<TUser>.ResetPasswordTokenPurpose);
                
                _logger.Here().Information("Password reset token generated for {UserType} user: {Email}", _userType, email);
                return TokenGenerationResult.Success(code);
            }
            else
            {
                _logger.Here().Warning("Password reset attempted for locked out {UserType} account: {Email}", _userType, email);
                return TokenGenerationResult.Failed("Account is locked");
            }
        }
        else
        {
            // User doesn't exist or email not confirmed - log but don't reveal this info
            _logger.Here().Warning("Password reset attempted for invalid or unconfirmed {UserType} email: {Email}", _userType, email);
            return TokenGenerationResult.Failed("Invalid email or account not confirmed");
        }
    }

    protected virtual string GetUserDisplayName(TUser user)
    {
        // Default implementation - can be overridden in derived classes
        return user.UserName ?? user.Email ?? "Unknown";
    }
} 