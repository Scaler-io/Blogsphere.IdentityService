namespace IdentityService.Models.Api.Account;

public class FieldErrorsDto
{
    public Dictionary<string, string[]> Errors { get; set; } = new();
}
