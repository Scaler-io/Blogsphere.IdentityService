using Duende.IdentityServer.Extensions;
using IdentityService.Models.Api.Account;
using IdentityService.Services.Account;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityService.Controllers;

[ApiController]
[Route("api/account")]
[AllowAnonymous]
[AutoValidateAntiforgeryToken]
public class AccountController(
    IAntiforgery antiforgery,
    ILoginFlowService loginFlowService,
    ITwoFactorFlowService twoFactorFlowService,
    IPasswordFlowService passwordFlowService,
    ILogoutFlowService logoutFlowService,
    IConsentFlowService consentFlowService,
    IDeviceFlowService deviceFlowService,
    IGrantsFlowService grantsFlowService) : ControllerBase
{
    [HttpGet("antiforgery")]
    [IgnoreAntiforgeryToken]
    public IActionResult GetAntiforgery()
    {
        var tokens = antiforgery.GetAndStoreTokens(HttpContext);
        return Ok(new AntiforgeryResponse { Token = tokens.RequestToken });
    }

    [HttpGet("login/context")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> GetLoginContext([FromQuery] string returnUrl)
    {
        var isAuthenticated = User.IsAuthenticated();
        var context = await loginFlowService.GetLoginContextAsync(returnUrl, isAuthenticated);

        if (isAuthenticated)
        {
            return Ok(context);
        }

        if (context.IsExternalLoginOnly)
        {
            return Ok(new LoginResponse
            {
                Outcome = LoginOutcome.ExternalLoginOnly,
                ExternalLoginScheme = context.ExternalLoginScheme,
                RedirectUrl = $"/ExternalLogin/Challenge?scheme={Uri.EscapeDataString(context.ExternalLoginScheme)}&returnUrl={Uri.EscapeDataString(context.ReturnUrl)}"
            });
        }

        return Ok(context);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var result = await loginFlowService.LoginAsync(request);
        return MapLoginResponse(result);
    }

    [HttpPost("login/cancel")]
    public async Task<IActionResult> CancelLogin([FromBody] LoginCancelRequest request)
    {
        var result = await loginFlowService.CancelLoginAsync(request);
        return Ok(result);
    }

    [HttpPost("two-factor/verify")]
    public async Task<IActionResult> VerifyTwoFactor([FromBody] TwoFactorVerifyRequest request)
    {
        var result = await twoFactorFlowService.VerifyAsync(request);
        return MapTwoFactorResponse(result);
    }

    [HttpPost("two-factor/resend")]
    public async Task<IActionResult> ResendTwoFactor([FromBody] TwoFactorResendRequest request)
    {
        var result = await twoFactorFlowService.ResendAsync(request);
        return MapTwoFactorResponse(result);
    }

    [HttpGet("logout/context")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> GetLogoutContext([FromQuery] string logoutId)
    {
        var context = await logoutFlowService.GetLogoutContextAsync(logoutId, User);
        return Ok(context);
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout([FromBody] LogoutRequest request)
    {
        var result = await logoutFlowService.LogoutAsync(request, User, BuildLoggedOutUrl);

        if (result.Outcome == LogoutOutcome.FederatedSignOutRequired)
        {
            return Ok(result);
        }

        return Ok(result);
    }

    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
    {
        var result = await passwordFlowService.ForgotPasswordAsync(request);

        if (result.FieldErrors?.Errors.Count > 0)
        {
            return BadRequest(result);
        }

        return Ok(result);
    }

    [HttpPost("reset-password/validate")]
    public async Task<IActionResult> ValidateResetToken([FromBody] ValidateResetTokenRequest request)
    {
        var result = await passwordFlowService.ValidateResetTokenAsync(request);
        return Ok(result);
    }

    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        var result = await passwordFlowService.ResetPasswordAsync(request);

        if (result.FieldErrors?.Errors.Count > 0)
        {
            return BadRequest(result);
        }

        if (!result.Success)
        {
            return BadRequest(result);
        }

        return Ok(result);
    }

    [HttpPost("self-reset-password/send-code")]
    [Authorize]
    public async Task<IActionResult> SelfResetSendCode([FromBody] SelfResetPasswordSendCodeRequest request)
    {
        var result = await passwordFlowService.SelfResetSendCodeAsync(User, request);
        return Ok(result);
    }

    [HttpPost("self-reset-password/verify-code")]
    [Authorize]
    public async Task<IActionResult> SelfResetVerifyCode([FromBody] SelfResetPasswordVerifyCodeRequest request)
    {
        var result = await passwordFlowService.SelfResetVerifyCodeAsync(User, request);

        if (result.FieldErrors?.Errors.Count > 0)
        {
            return BadRequest(result);
        }

        return Ok(result);
    }

    [HttpPost("self-reset-password/change-password")]
    [Authorize]
    public async Task<IActionResult> SelfResetChangePassword([FromBody] SelfResetPasswordChangeRequest request)
    {
        var result = await passwordFlowService.SelfResetChangePasswordAsync(User, request);

        if (result.FieldErrors?.Errors.Count > 0)
        {
            return BadRequest(result);
        }

        return Ok(result);
    }

    [HttpGet("manage")]
    [Authorize]
    public IActionResult GetManage()
    {
        return StatusCode(StatusCodes.Status501NotImplemented, new ManageStubResponse
        {
            Implemented = false,
            Message = "Account management is not yet implemented via API."
        });
    }

    [HttpPost("manage")]
    [Authorize]
    public IActionResult PostManage()
    {
        return StatusCode(StatusCodes.Status501NotImplemented, new ManageStubResponse
        {
            Implemented = false,
            Message = "Account management is not yet implemented via API."
        });
    }

    [HttpGet("consent/context")]
    [Authorize]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> GetConsentContext([FromQuery] string returnUrl)
    {
        var result = await consentFlowService.GetContextAsync(returnUrl);

        if (result == null)
        {
            return NotFound();
        }

        return Ok(result);
    }

    [HttpPost("consent")]
    [Authorize]
    public async Task<IActionResult> SubmitConsent([FromBody] ConsentSubmitRequest request)
    {
        var result = await consentFlowService.SubmitAsync(request, User);

        if (!result.Success)
        {
            return BadRequest(result);
        }

        return Ok(result);
    }

    [HttpGet("device/context")]
    [Authorize]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> GetDeviceContext([FromQuery] string userCode)
    {
        var result = await deviceFlowService.GetContextAsync(userCode);

        if (!result.Success)
        {
            return BadRequest(result);
        }

        return Ok(result);
    }

    [HttpPost("device")]
    [Authorize]
    public async Task<IActionResult> SubmitDevice([FromBody] DeviceSubmitRequest request)
    {
        var result = await deviceFlowService.SubmitAsync(request, User);

        if (!result.Success)
        {
            return BadRequest(result);
        }

        return Ok(result);
    }

    [HttpGet("grants")]
    [Authorize]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> GetGrants()
    {
        var result = await grantsFlowService.GetGrantsAsync(User);
        return Ok(result);
    }

    [HttpPost("grants/revoke")]
    [Authorize]
    public async Task<IActionResult> RevokeGrant([FromBody] RevokeGrantRequest request)
    {
        var result = await grantsFlowService.RevokeGrantAsync(request, User);
        return Ok(result);
    }

    private IActionResult MapLoginResponse(LoginResponse result)
    {
        return result.Outcome switch
        {
            LoginOutcome.Failed => BadRequest(result),
            LoginOutcome.LockedOut => StatusCode(StatusCodes.Status423Locked, result),
            _ => Ok(result)
        };
    }

    private IActionResult MapTwoFactorResponse(TwoFactorResponse result)
    {
        return result.Outcome switch
        {
            TwoFactorOutcome.Failed => BadRequest(result),
            TwoFactorOutcome.SessionExpired => BadRequest(result),
            _ => Ok(result)
        };
    }

    private string BuildLoggedOutUrl(string logoutId)
    {
        return Url.Page("/Account/Logout/LoggedOut", values: new { logoutId }) ?? "/Account/Logout/LoggedOut";
    }
}
