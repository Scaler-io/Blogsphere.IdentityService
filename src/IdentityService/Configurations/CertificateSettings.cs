namespace IdentityService.Configurations;

public class CertificateSettings
{
    public static string OptionName {get; set; } = "Certificate";
    public string Path { get; set; }
    public string Password { get; set; }
}
