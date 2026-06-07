namespace IdentityService.Models.Api.Account;

public class TwoFactorVerifyRequest
{
    public string TwoFactorSessionId { get; set; }

    public string Code { get; set; }
}

public class TwoFactorResendRequest
{
    public string TwoFactorSessionId { get; set; }
}

public enum TwoFactorOutcome
{
    Success,
    Failed,
    SessionExpired
}

public class TwoFactorResponse
{
    public TwoFactorOutcome Outcome { get; set; }

    public string RedirectUrl { get; set; }

    public bool IsNativeClient { get; set; }

    public string StatusMessage { get; set; }

    public FieldErrorsDto FieldErrors { get; set; }
}
