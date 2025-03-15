namespace IdentityService.Entities;

public class ProfileDetails
{
    public bool HasData { get; set; } = true;
    public string Bio { get; set; } = string.Empty;
    public string WebsiteUrl { get; set; } = string.Empty;
    public string LinkedIn { get; set; } = string.Empty;
    public string Twitter { get; set; } = string.Empty;
    public string Instagram { get; set; } = string.Empty;
}
