using System.Runtime.Serialization;

namespace IdentityService.Models.Enums;

public enum Roles
{
    [EnumMember(Value = "EDITOR")]
    Editor,
    [EnumMember(Value = "AUTHOR")]
    Author,
    [EnumMember(Value = "SUBSCRIBER")]
    Subscriber
}