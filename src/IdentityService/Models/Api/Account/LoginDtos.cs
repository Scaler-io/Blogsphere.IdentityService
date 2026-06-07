namespace IdentityService.Models.Api.Account;

public class LoginContextResponse
{
    public bool AllowRememberLogin { get; set; }

    public bool EnableLocalLogin { get; set; }

    public bool ShowSignup { get; set; }

    public string ReturnUrl { get; set; }

    public string Username { get; set; }

    public bool IsExternalLoginOnly { get; set; }

    public string ExternalLoginScheme { get; set; }

    public bool IsAuthenticated { get; set; }

    public IEnumerable<ExternalProviderDto> ExternalProviders { get; set; } = [];
}

public class ExternalProviderDto
{
    public string AuthenticationScheme { get; set; }

    public string DisplayName { get; set; }
}

public class LoginRequest
{
    public string Username { get; set; }

    public string Password { get; set; }

    public bool RememberLogin { get; set; }

    public string ReturnUrl { get; set; }
}

public class LoginCancelRequest
{
    public string ReturnUrl { get; set; }
}

public enum LoginOutcome
{
    Success,
    RequiresTwoFactor,
    Failed,
    LockedOut,
    Cancelled,
    ExternalLoginOnly,
    AlreadyAuthenticated
}

public class LoginResponse
{
    public LoginOutcome Outcome { get; set; }

    public string RedirectUrl { get; set; }

    public bool IsNativeClient { get; set; }

    public string TwoFactorSessionId { get; set; }

    public string ExternalLoginScheme { get; set; }

    public FieldErrorsDto FieldErrors { get; set; }
}
