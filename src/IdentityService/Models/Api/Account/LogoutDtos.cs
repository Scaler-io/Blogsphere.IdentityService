namespace IdentityService.Models.Api.Account;

public class LogoutRequest
{
    public string LogoutId { get; set; }
}

public enum LogoutOutcome
{
    Success,
    FederatedSignOutRequired,
    NotAuthenticated
}

public class LogoutResponse
{
    public LogoutOutcome Outcome { get; set; }

    public string RedirectUrl { get; set; }

    public string LogoutId { get; set; }

    public string FederatedSignOutScheme { get; set; }
}

public class LogoutContextResponse
{
    public bool ShowLogoutPrompt { get; set; }

    public string LogoutId { get; set; }

    public bool IsAuthenticated { get; set; }
}
