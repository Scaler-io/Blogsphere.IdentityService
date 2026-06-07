using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Contracts.Events;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;
using IdentityService.Entities;
using IdentityService.Extensions;
using IdentityService.Management.Entities;
using IdentityService.Management.Models;
using IdentityService.Management.Services;
using IdentityService.Models.Api.Account;
using IdentityService.Security;
using IdentityService.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;

namespace IdentityService.Services.Account;

public class PasswordFlowService(
    ILogger logger,
    IMultiUserStoreService multiUserStoreService,
    IApplicationUserAuthenticationService applicationUserAuthService,
    IManagementUserAuthenticationService managementUserAuthService,
    IPublishService publishService,
    UserManager<ApplicationUser> userManager,
    UserManager<ManagementUser> managementUserManager,
    SignInManager<ApplicationUser> signInManager,
    SignInManager<ManagementUser> managementSignInManager,
    IPersistedGrantStore persistedGrantStore,
    IHttpContextAccessor httpContextAccessor) : IPasswordFlowService
{
    private const string OtpLoginProvider = "SelfResetPassword";
    private const string OtpCodeName = "OtpCode";
    private const string OtpCodeExpiryName = "OtpCodeExpiry";
    private const string OtpVerifiedName = "OtpVerified";
    private const int OtpExpiryMinutes = 10;

    public async Task<ForgotPasswordResponse> ForgotPasswordAsync(ForgotPasswordRequest request)
    {
        var returnUrl = ReturnUrlGuard.NormalizeForClientApp(request.ReturnUrl, request.ClientId);
        var fieldErrors = new FieldErrorsDto();

        if (string.IsNullOrWhiteSpace(request.Email))
        {
            fieldErrors.Errors["email"] = ["Please enter a valid email address"];
            return new ForgotPasswordResponse { Success = false, FieldErrors = fieldErrors };
        }

        try
        {
            var email = request.Email.Trim().ToLowerInvariant();
            var userStore = await multiUserStoreService.DetermineUserStoreByEmailAsync(email);

            logger.Here().Information("=== FORGOT PASSWORD DEBUG === Email: {Email}, UserStore: {UserStore}", email, userStore);

            if (userStore == ManagementConstants.ManagementUserStore)
            {
                var tokenResult = await managementUserAuthService.GeneratePasswordResetTokenAsync(email);
                if (tokenResult.IsSuccess)
                {
                    await publishService.PublishAsync<PasswordResetInstructionSent>(new()
                    {
                        Email = email,
                    }, Guid.NewGuid().ToString(), new
                    {
                        Token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(tokenResult.Token)),
                        UserType = "management",
                        ReturnUrl = returnUrl,
                        ClientId = request.ClientId
                    });
                }
            }
            else
            {
                var tokenResult = await applicationUserAuthService.GeneratePasswordResetTokenAsync(email);
                if (tokenResult.IsSuccess)
                {
                    await publishService.PublishAsync<PasswordResetInstructionSent>(new()
                    {
                        Email = email,
                    }, Guid.NewGuid().ToString(), new
                    {
                        Token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(tokenResult.Token)),
                        UserType = "blogsphere",
                        ReturnUrl = returnUrl,
                        ClientId = request.ClientId
                    });
                }
            }

            return new ForgotPasswordResponse
            {
                Success = true,
                Message = "If an account with that email exists, password reset instructions have been sent."
            };
        }
        catch (Exception ex)
        {
            logger.Here().Error(ex, "Error in password reset for \"{Email}\"", request.Email);
            return new ForgotPasswordResponse
            {
                Success = false,
                Message = "An error occurred while processing your request. Please try again later."
            };
        }
    }

    public async Task<ValidateResetTokenResponse> ValidateResetTokenAsync(ValidateResetTokenRequest request)
    {
        var returnUrl = ReturnUrlGuard.NormalizeForClientApp(request.ReturnUrl, request.ClientId);

        if (string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Token))
        {
            return new ValidateResetTokenResponse { IsValid = false, ReturnUrl = returnUrl };
        }

        var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(request.Token));
        var userStore = await multiUserStoreService.DetermineUserStoreByEmailAsync(request.Email);

        if (userStore == ManagementConstants.ManagementUserStore)
        {
            var result = await managementUserAuthService.ValidatePasswordResetTokenAsync(request.Email, decodedToken);
            return new ValidateResetTokenResponse { IsValid = result.IsValid, ReturnUrl = returnUrl };
        }

        var appResult = await applicationUserAuthService.ValidatePasswordResetTokenAsync(request.Email, decodedToken);
        return new ValidateResetTokenResponse { IsValid = appResult.IsValid, ReturnUrl = returnUrl };
    }

    public async Task<ResetPasswordResponse> ResetPasswordAsync(ResetPasswordRequest request)
    {
        var returnUrl = ReturnUrlGuard.NormalizeForClientApp(request.ReturnUrl, request.ClientId);
        var fieldErrors = new FieldErrorsDto();

        if (string.IsNullOrWhiteSpace(request.Password))
        {
            fieldErrors.Errors["password"] = ["Password is required."];
        }

        if (!string.Equals(request.Password, request.ConfirmPassword, StringComparison.Ordinal))
        {
            fieldErrors.Errors["confirmPassword"] = ["The password and confirmation password do not match."];
        }

        if (string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Token))
        {
            return new ResetPasswordResponse
            {
                Success = false,
                RedirectUrl = $"/Account/Login?returnUrl={Uri.EscapeDataString(returnUrl)}",
                Message = "Invalid reset request."
            };
        }

        if (fieldErrors.Errors.Count > 0)
        {
            return new ResetPasswordResponse { Success = false, FieldErrors = fieldErrors };
        }

        var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(request.Token));
        var userStore = await multiUserStoreService.DetermineUserStoreByEmailAsync(request.Email);

        logger.Here().Information("=== RESET PASSWORD DEBUG === Email: {Email}, UserStore: {UserStore}", request.Email, userStore);

        PasswordResetResult result;
        string subjectId;

        if (userStore == ManagementConstants.ManagementUserStore)
        {
            result = await managementUserAuthService.ResetPasswordAsync(request.Email, decodedToken, request.Password);
            var managementUser = await managementUserManager.FindByEmailAsync(request.Email);
            subjectId = managementUser?.Id;
        }
        else
        {
            result = await applicationUserAuthService.ResetPasswordAsync(request.Email, decodedToken, request.Password);
            var appUser = await userManager.FindByEmailAsync(request.Email);
            subjectId = appUser?.Id;
        }

        if (!result.IsSuccess)
        {
            fieldErrors.Errors[""] = [result.ErrorMessage];
            return new ResetPasswordResponse { Success = false, FieldErrors = fieldErrors };
        }

        if (!string.IsNullOrEmpty(subjectId))
        {
            await RevokeTokensAndSignOutAsync(subjectId, request.Email);
        }

        return new ResetPasswordResponse
        {
            Success = true,
            RedirectUrl = $"/Account/Login?returnUrl={Uri.EscapeDataString(returnUrl)}"
        };
    }

    public async Task<SelfResetPasswordResponse> SelfResetSendCodeAsync(ClaimsPrincipal principal, SelfResetPasswordSendCodeRequest request)
    {
        var returnUrl = ReturnUrlGuard.NormalizeForClientApp(request.ReturnUrl, request.ClientId);
        var currentEmail = GetCurrentUserEmail(principal);

        if (string.IsNullOrWhiteSpace(currentEmail))
        {
            return new SelfResetPasswordResponse
            {
                Success = false,
                RedirectUrl = $"/Account/Login?returnUrl={Uri.EscapeDataString(returnUrl)}"
            };
        }

        var userStore = await multiUserStoreService.DetermineUserStoreByEmailAsync(currentEmail);
        var oneTimeCode = RandomNumberGenerator.GetInt32(100000, 1000000).ToString("D6");
        await SaveOtpAsync(currentEmail, userStore, oneTimeCode, DateTime.UtcNow.AddMinutes(OtpExpiryMinutes), isVerified: false);

        await publishService.PublishAsync(new AuthCodeSent
        {
            Email = currentEmail,
            Code = oneTimeCode
        }, Guid.NewGuid().ToString(), new
        {
            Purpose = "SelfResetPassword",
            UserType = userStore == ManagementConstants.ManagementUserStore ? "management" : "blogsphere",
        });

        return new SelfResetPasswordResponse
        {
            Success = true,
            Message = "One-time code sent to your email."
        };
    }

    public async Task<SelfResetPasswordResponse> SelfResetVerifyCodeAsync(ClaimsPrincipal principal, SelfResetPasswordVerifyCodeRequest request)
    {
        var returnUrl = ReturnUrlGuard.NormalizeForClientApp(request.ReturnUrl, request.ClientId);
        var currentEmail = GetCurrentUserEmail(principal);
        var fieldErrors = new FieldErrorsDto();

        if (string.IsNullOrWhiteSpace(currentEmail))
        {
            return new SelfResetPasswordResponse
            {
                Success = false,
                RedirectUrl = $"/Account/Login?returnUrl={Uri.EscapeDataString(returnUrl)}"
            };
        }

        if (string.IsNullOrWhiteSpace(request.OneTimeCode))
        {
            fieldErrors.Errors["oneTimeCode"] = ["One-time code is required."];
            return new SelfResetPasswordResponse { Success = false, FieldErrors = fieldErrors };
        }

        var userStore = await multiUserStoreService.DetermineUserStoreByEmailAsync(currentEmail);
        var (isValid, reason) = await ValidateOtpAsync(currentEmail, userStore, request.OneTimeCode);

        if (!isValid)
        {
            fieldErrors.Errors["oneTimeCode"] = [reason];
            return new SelfResetPasswordResponse { Success = false, FieldErrors = fieldErrors };
        }

        await SetOtpVerifiedAsync(currentEmail, userStore, isVerified: true);

        return new SelfResetPasswordResponse { Success = true, Message = "Code verified." };
    }

    public async Task<SelfResetPasswordResponse> SelfResetChangePasswordAsync(ClaimsPrincipal principal, SelfResetPasswordChangeRequest request)
    {
        var returnUrl = ReturnUrlGuard.NormalizeForClientApp(request.ReturnUrl, request.ClientId);
        var currentEmail = GetCurrentUserEmail(principal);
        var fieldErrors = new FieldErrorsDto();

        if (string.IsNullOrWhiteSpace(currentEmail))
        {
            return new SelfResetPasswordResponse
            {
                Success = false,
                RedirectUrl = $"/Account/Login?returnUrl={Uri.EscapeDataString(returnUrl)}"
            };
        }

        var userStore = await multiUserStoreService.DetermineUserStoreByEmailAsync(currentEmail);
        var codeMode = string.Equals(request.Mode, "code", StringComparison.OrdinalIgnoreCase);

        if (codeMode && !await IsOtpVerifiedAsync(currentEmail, userStore))
        {
            fieldErrors.Errors[""] = ["One-time code verification is required."];
            return new SelfResetPasswordResponse { Success = false, FieldErrors = fieldErrors };
        }

        if (!codeMode && string.IsNullOrWhiteSpace(request.CurrentPassword))
        {
            fieldErrors.Errors["currentPassword"] = ["Current password is required."];
        }

        if (string.IsNullOrWhiteSpace(request.NewPassword))
        {
            fieldErrors.Errors["newPassword"] = ["New password is required."];
        }

        if (!string.Equals(request.NewPassword, request.ConfirmPassword, StringComparison.Ordinal))
        {
            fieldErrors.Errors["confirmPassword"] = ["The password and confirmation password do not match."];
        }

        if (fieldErrors.Errors.Count > 0)
        {
            return new SelfResetPasswordResponse { Success = false, FieldErrors = fieldErrors };
        }

        if (userStore == ManagementConstants.ManagementUserStore)
        {
            return await ChangeManagementPasswordAsync(currentEmail, request, codeMode, returnUrl, fieldErrors);
        }

        return await ChangeApplicationPasswordAsync(currentEmail, request, codeMode, returnUrl, fieldErrors);
    }

    private async Task<SelfResetPasswordResponse> ChangeManagementPasswordAsync(
        string currentEmail,
        SelfResetPasswordChangeRequest request,
        bool codeMode,
        string returnUrl,
        FieldErrorsDto fieldErrors)
    {
        var managementUser = await managementUserManager.FindByEmailAsync(currentEmail);
        if (managementUser == null)
        {
            return new SelfResetPasswordResponse
            {
                Success = false,
                RedirectUrl = $"/Account/Login?returnUrl={Uri.EscapeDataString(returnUrl)}"
            };
        }

        IdentityResult result;
        if (codeMode)
        {
            await managementUserManager.RemovePasswordAsync(managementUser);
            result = await managementUserManager.AddPasswordAsync(managementUser, request.NewPassword);
        }
        else
        {
            var isCurrentPasswordValid = await managementUserManager.CheckPasswordAsync(managementUser, request.CurrentPassword);
            if (!isCurrentPasswordValid)
            {
                fieldErrors.Errors["currentPassword"] = ["Current password is incorrect."];
                return new SelfResetPasswordResponse { Success = false, FieldErrors = fieldErrors };
            }

            result = await managementUserManager.ChangePasswordAsync(managementUser, request.CurrentPassword, request.NewPassword);
        }

        if (!result.Succeeded)
        {
            AddIdentityErrors(result, fieldErrors, codeMode);
            return new SelfResetPasswordResponse { Success = false, FieldErrors = fieldErrors };
        }

        if (codeMode)
        {
            await ClearOtpAsync(currentEmail, ManagementConstants.ManagementUserStore);
        }

        await RevokeTokensAndSignOutAsync(managementUser.Id, currentEmail);
        await managementSignInManager.PasswordSignInAsync(managementUser, request.NewPassword, isPersistent: true, lockoutOnFailure: false);

        return new SelfResetPasswordResponse
        {
            Success = true,
            RedirectUrl = AppendPasswordResetParam(returnUrl)
        };
    }

    private async Task<SelfResetPasswordResponse> ChangeApplicationPasswordAsync(
        string currentEmail,
        SelfResetPasswordChangeRequest request,
        bool codeMode,
        string returnUrl,
        FieldErrorsDto fieldErrors)
    {
        var appUser = await userManager.FindByEmailAsync(currentEmail);
        if (appUser == null)
        {
            return new SelfResetPasswordResponse
            {
                Success = false,
                RedirectUrl = $"/Account/Login?returnUrl={Uri.EscapeDataString(returnUrl)}"
            };
        }

        IdentityResult result;
        if (codeMode)
        {
            await userManager.RemovePasswordAsync(appUser);
            result = await userManager.AddPasswordAsync(appUser, request.NewPassword);
        }
        else
        {
            var isCurrentPasswordValid = await userManager.CheckPasswordAsync(appUser, request.CurrentPassword);
            if (!isCurrentPasswordValid)
            {
                fieldErrors.Errors["currentPassword"] = ["Current password is incorrect."];
                return new SelfResetPasswordResponse { Success = false, FieldErrors = fieldErrors };
            }

            result = await userManager.ChangePasswordAsync(appUser, request.CurrentPassword, request.NewPassword);
        }

        if (!result.Succeeded)
        {
            AddIdentityErrors(result, fieldErrors, codeMode);
            return new SelfResetPasswordResponse { Success = false, FieldErrors = fieldErrors };
        }

        if (codeMode)
        {
            await ClearOtpAsync(currentEmail, ManagementConstants.BlogsphereUserStore);
        }

        await RevokeTokensAndSignOutAsync(appUser.Id, currentEmail);
        await signInManager.PasswordSignInAsync(appUser, request.NewPassword, isPersistent: true, lockoutOnFailure: false);

        return new SelfResetPasswordResponse
        {
            Success = true,
            RedirectUrl = AppendPasswordResetParam(returnUrl)
        };
    }

    private static void AddIdentityErrors(IdentityResult result, FieldErrorsDto fieldErrors, bool codeMode)
    {
        foreach (var error in result.Errors)
        {
            var isCurrentPasswordError = !codeMode
                && (string.Equals(error.Code, "PasswordMismatch", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(error.Code, "InvalidPassword", StringComparison.OrdinalIgnoreCase)
                    || error.Description.Contains("incorrect password", StringComparison.OrdinalIgnoreCase)
                    || error.Description.Contains("password mismatch", StringComparison.OrdinalIgnoreCase));

            if (isCurrentPasswordError)
            {
                fieldErrors.Errors["currentPassword"] = [error.Description];
            }
            else
            {
                if (!fieldErrors.Errors.ContainsKey(""))
                {
                    fieldErrors.Errors[""] = [];
                }

                fieldErrors.Errors[""] = fieldErrors.Errors[""].Append(error.Description).ToArray();
            }
        }
    }

    private async Task RevokeTokensAndSignOutAsync(string subjectId, string email)
    {
        await persistedGrantStore.RemoveAllAsync(new PersistedGrantFilter { SubjectId = subjectId });
        await signInManager.SignOutAsync();
        await managementSignInManager.SignOutAsync();

        if (httpContextAccessor.HttpContext != null)
        {
            await httpContextAccessor.HttpContext.SignOutAsync();
        }

        logger.Here().Information("Revoked persisted grants and signed out user after password reset for {Email}", email);
    }

    private static string GetCurrentUserEmail(ClaimsPrincipal principal)
    {
        return principal.FindFirstValue(ClaimTypes.Email)
            ?? principal.FindFirstValue("email")
            ?? principal.Identity?.Name
            ?? string.Empty;
    }

    private static string AppendPasswordResetParam(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return url;
        var separator = url.Contains('?') ? "&" : "?";
        return url + separator + "passwordReset=success";
    }

    private async Task SaveOtpAsync(string email, string userStore, string code, DateTime expiryUtc, bool isVerified)
    {
        if (userStore == ManagementConstants.ManagementUserStore)
        {
            var user = await managementUserManager.FindByEmailAsync(email);
            if (user == null) return;

            await managementUserManager.SetAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeName, code);
            await managementUserManager.SetAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeExpiryName, expiryUtc.ToString("O"));
            await managementUserManager.SetAuthenticationTokenAsync(user, OtpLoginProvider, OtpVerifiedName, isVerified.ToString());
            return;
        }

        var appUser = await userManager.FindByEmailAsync(email);
        if (appUser == null) return;

        await userManager.SetAuthenticationTokenAsync(appUser, OtpLoginProvider, OtpCodeName, code);
        await userManager.SetAuthenticationTokenAsync(appUser, OtpLoginProvider, OtpCodeExpiryName, expiryUtc.ToString("O"));
        await userManager.SetAuthenticationTokenAsync(appUser, OtpLoginProvider, OtpVerifiedName, isVerified.ToString());
    }

    private async Task<(bool isValid, string reason)> ValidateOtpAsync(string email, string userStore, string otpCode)
    {
        string savedCode;
        string expiryRaw;

        if (userStore == ManagementConstants.ManagementUserStore)
        {
            var user = await managementUserManager.FindByEmailAsync(email);
            if (user == null) return (false, "Invalid user.");
            savedCode = await managementUserManager.GetAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeName) ?? string.Empty;
            expiryRaw = await managementUserManager.GetAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeExpiryName) ?? string.Empty;
        }
        else
        {
            var appUser = await userManager.FindByEmailAsync(email);
            if (appUser == null) return (false, "Invalid user.");
            savedCode = await userManager.GetAuthenticationTokenAsync(appUser, OtpLoginProvider, OtpCodeName) ?? string.Empty;
            expiryRaw = await userManager.GetAuthenticationTokenAsync(appUser, OtpLoginProvider, OtpCodeExpiryName) ?? string.Empty;
        }

        return ValidateOtpToken(savedCode, expiryRaw, otpCode);
    }

    private static (bool isValid, string reason) ValidateOtpToken(string savedCode, string expiryRaw, string otpCode)
    {
        if (string.IsNullOrWhiteSpace(savedCode) || string.IsNullOrWhiteSpace(expiryRaw))
            return (false, "No active one-time code. Please request a new code.");

        if (!DateTime.TryParse(expiryRaw, out var expiryUtc) || DateTime.UtcNow > expiryUtc)
            return (false, "One-time code expired. Please request a new code.");

        if (!string.Equals(savedCode, otpCode, StringComparison.Ordinal))
            return (false, "Invalid one-time code.");

        return (true, string.Empty);
    }

    private async Task SetOtpVerifiedAsync(string email, string userStore, bool isVerified)
    {
        if (userStore == ManagementConstants.ManagementUserStore)
        {
            var user = await managementUserManager.FindByEmailAsync(email);
            if (user == null) return;
            await managementUserManager.SetAuthenticationTokenAsync(user, OtpLoginProvider, OtpVerifiedName, isVerified.ToString());
            return;
        }

        var appUser = await userManager.FindByEmailAsync(email);
        if (appUser == null) return;
        await userManager.SetAuthenticationTokenAsync(appUser, OtpLoginProvider, OtpVerifiedName, isVerified.ToString());
    }

    private async Task<bool> IsOtpVerifiedAsync(string email, string userStore)
    {
        if (userStore == ManagementConstants.ManagementUserStore)
        {
            var user = await managementUserManager.FindByEmailAsync(email);
            if (user == null) return false;
            var isVerifiedRaw = await managementUserManager.GetAuthenticationTokenAsync(user, OtpLoginProvider, OtpVerifiedName);
            return bool.TryParse(isVerifiedRaw, out var isVerified) && isVerified;
        }

        var appUser = await userManager.FindByEmailAsync(email);
        if (appUser == null) return false;
        var appVerifiedRaw = await userManager.GetAuthenticationTokenAsync(appUser, OtpLoginProvider, OtpVerifiedName);
        return bool.TryParse(appVerifiedRaw, out var appVerified) && appVerified;
    }

    private async Task ClearOtpAsync(string email, string userStore)
    {
        if (userStore == ManagementConstants.ManagementUserStore)
        {
            var user = await managementUserManager.FindByEmailAsync(email);
            if (user == null) return;

            await managementUserManager.RemoveAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeName);
            await managementUserManager.RemoveAuthenticationTokenAsync(user, OtpLoginProvider, OtpCodeExpiryName);
            await managementUserManager.RemoveAuthenticationTokenAsync(user, OtpLoginProvider, OtpVerifiedName);
            return;
        }

        var appUser = await userManager.FindByEmailAsync(email);
        if (appUser == null) return;

        await userManager.RemoveAuthenticationTokenAsync(appUser, OtpLoginProvider, OtpCodeName);
        await userManager.RemoveAuthenticationTokenAsync(appUser, OtpLoginProvider, OtpCodeExpiryName);
        await userManager.RemoveAuthenticationTokenAsync(appUser, OtpLoginProvider, OtpVerifiedName);
    }
}
