using System.Runtime.Serialization;

namespace IdentityService.Extensions;

public static class EnumExtensions
{
    public static string GetEnumMemberAttributeValue<TEnum>(this TEnum enumValue) where TEnum : struct
    {
        var enumType = typeof(TEnum);
        var memberInfo = enumType.GetMember(enumValue.ToString());

        if(memberInfo.Length > 0)
        {
            var attributes = memberInfo[0].GetCustomAttributes(typeof(EnumMemberAttribute), false);
            if(attributes.Length > 0)
            {
                return ((EnumMemberAttribute)attributes[0]).Value;
            }
        }

        throw new ArgumentException($"Enum member '{enumValue}' does not have a [EnumMember] attribute with a value.");
    }
}
