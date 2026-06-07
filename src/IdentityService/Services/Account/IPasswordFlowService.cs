using IdentityService.Models.Api.Account;
using System.Security.Claims;

namespace IdentityService.Services.Account;

public interface IPasswordFlowService
{
    Task<ForgotPasswordResponse> ForgotPasswordAsync(ForgotPasswordRequest request);

    Task<ValidateResetTokenResponse> ValidateResetTokenAsync(ValidateResetTokenRequest request);

    Task<ResetPasswordResponse> ResetPasswordAsync(ResetPasswordRequest request);

    Task<SelfResetPasswordResponse> SelfResetSendCodeAsync(ClaimsPrincipal user, SelfResetPasswordSendCodeRequest request);

    Task<SelfResetPasswordResponse> SelfResetVerifyCodeAsync(ClaimsPrincipal user, SelfResetPasswordVerifyCodeRequest request);

    Task<SelfResetPasswordResponse> SelfResetChangePasswordAsync(ClaimsPrincipal user, SelfResetPasswordChangeRequest request);
}
