using IdentityService.Management.Models.Enums;
using IdentityService.Models;

namespace IdentityService.Tests;

public class IdGeneratorTests
{
    [Theory]
    [InlineData(nameof(ManagementRoles.Manager), "MGR")]
    [InlineData(nameof(ManagementRoles.SuperAdmin), "SAD")]
    [InlineData(nameof(ManagementRoles.Admin), "ADM")]
    [InlineData(nameof(ManagementRoles.Moderator), "MOD")]
    [InlineData(nameof(ManagementRoles.Analyst), "ANL")]
    [InlineData(nameof(ManagementRoles.Support), "SUP")]
    [InlineData(nameof(ManagementRoles.SystemAdmin), "SYS")]
    [InlineData("manager", "MGR")]
    [InlineData("ADM", "ADM")]
    [InlineData("mgr", "MGR")]
    public void ResolveRoleAbbreviation_MapsRoleNamesAndAbbreviations(string role, string expected)
    {
        var result = IdGenerator.ResolveRoleAbbreviation(role);

        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("ops", "OPS")]
    [InlineData(" IT ", "IT")]
    public void NormalizeDepartment_TrimsAndUppercases(string department, string expected)
    {
        var result = IdGenerator.NormalizeDepartment(department);

        Assert.Equal(expected, result);
    }

    [Fact]
    public void NewManagementUserId_ManagerRole_UsesAbbreviationNotFullRoleName()
    {
        var id = IdGenerator.NewManagementUserId("OPS", nameof(ManagementRoles.Manager));

        Assert.StartsWith("OPSMGR", id);
        Assert.DoesNotContain("Manager", id);
        Assert.True(id.Length <= IdGenerator.MaxManagementEmployeeIdLength);
    }

    [Fact]
    public void NewManagementUserId_AdminRole_UsesAbbreviation()
    {
        var id = IdGenerator.NewManagementUserId("IT", nameof(ManagementRoles.Admin));

        Assert.StartsWith("ITADM", id);
        Assert.True(id.Length <= IdGenerator.MaxManagementEmployeeIdLength);
    }

    [Fact]
    public void NewManagementUserId_PassedAbbreviation_RemainsCompatible()
    {
        var id = IdGenerator.NewManagementUserId("IT", "ADM");

        Assert.StartsWith("ITADM", id);
    }

    [Fact]
    public void NewManagementUserId_SuperAdminRole_DoesNotEmbedFullRoleName()
    {
        var id = IdGenerator.NewManagementUserId("OPS", nameof(ManagementRoles.SuperAdmin));

        Assert.StartsWith("OPSSAD", id);
        Assert.DoesNotContain("SuperAdmin", id);
        Assert.True(id.Length <= IdGenerator.MaxManagementEmployeeIdLength);
    }

    [Fact]
    public void NewManagementUserId_NormalizesDepartmentCase()
    {
        var id = IdGenerator.NewManagementUserId("ops", "manager");

        Assert.StartsWith("OPSMGR", id);
    }

    [Fact]
    public void NewManagementUserId_Format_IsDeptRoleDateSuffix()
    {
        var id = IdGenerator.NewManagementUserId("OPS", "Manager");
        var datePart = DateTime.UtcNow.ToString("yyMMdd");

        Assert.StartsWith($"OPSMGR{datePart}", id);
        Assert.Equal(16, id.Length);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ResolveRoleAbbreviation_ThrowsForMissingRole(string role)
    {
        Assert.Throws<ArgumentException>(() => IdGenerator.ResolveRoleAbbreviation(role));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void NormalizeDepartment_ThrowsForMissingDepartment(string department)
    {
        Assert.Throws<ArgumentException>(() => IdGenerator.NormalizeDepartment(department));
    }
}
