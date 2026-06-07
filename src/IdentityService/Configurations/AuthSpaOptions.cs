namespace IdentityService.Configurations;

public class AuthSpaOptions
{
    public const string SectionName = "AuthSpa";

    public bool Enabled { get; set; }

    public string BaseUrl { get; set; } = "http://localhost:4201";
}
