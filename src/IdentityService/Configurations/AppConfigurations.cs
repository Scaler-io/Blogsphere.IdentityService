namespace IdentityService.Configurations;

public class AppConfigurations
{
    public const string AppConfigName = "AppConfigurations";
    public string ApplicationIdentifier { get; set; }
    public string ApplicationEnvironment { get; set; }
    public string LoginProvider { get; set; }
    public string ProviderDisplayName { get; set; }
    public string ProviderKey { get; set; }
}
