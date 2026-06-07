namespace IdentityService.Models.Api.Account;

public class ForgotPasswordRequest
{
    public string Email { get; set; }

    public string ReturnUrl { get; set; }

    public string ClientId { get; set; }
}

public class ForgotPasswordResponse
{
    public bool Success { get; set; }

    public string Message { get; set; }

    public FieldErrorsDto FieldErrors { get; set; }
}

public class ValidateResetTokenRequest
{
    public string Email { get; set; }

    public string Token { get; set; }

    public string ReturnUrl { get; set; }

    public string ClientId { get; set; }
}

public class ValidateResetTokenResponse
{
    public bool IsValid { get; set; }

    public string ReturnUrl { get; set; }
}

public class ResetPasswordRequest
{
    public string Email { get; set; }

    public string Token { get; set; }

    public string Password { get; set; }

    public string ConfirmPassword { get; set; }

    public string ReturnUrl { get; set; }

    public string ClientId { get; set; }
}

public class ResetPasswordResponse
{
    public bool Success { get; set; }

    public string RedirectUrl { get; set; }

    public string Message { get; set; }

    public FieldErrorsDto FieldErrors { get; set; }
}

public class SelfResetPasswordSendCodeRequest
{
    public string ReturnUrl { get; set; }

    public string ClientId { get; set; }
}

public class SelfResetPasswordVerifyCodeRequest
{
    public string OneTimeCode { get; set; }

    public string ReturnUrl { get; set; }

    public string ClientId { get; set; }
}

public class SelfResetPasswordChangeRequest
{
    public string Mode { get; set; } = "current";

    public string CurrentPassword { get; set; }

    public string NewPassword { get; set; }

    public string ConfirmPassword { get; set; }

    public string ReturnUrl { get; set; }

    public string ClientId { get; set; }
}

public class SelfResetPasswordResponse
{
    public bool Success { get; set; }

    public string RedirectUrl { get; set; }

    public string Message { get; set; }

    public FieldErrorsDto FieldErrors { get; set; }
}
