namespace IdentityService.Models.Api.Account;

public class AntiforgeryResponse
{
    public string Token { get; set; }

    public string HeaderName { get; set; } = "X-XSRF-TOKEN";
}
