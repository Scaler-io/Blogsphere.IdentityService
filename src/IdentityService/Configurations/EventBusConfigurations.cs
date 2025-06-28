using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityService.Configurations;

public class EventBusConfigurations
{
    public static string OptionName {get; set; } = "EventBus";
    public string Host { get; set; }
    public string Username { get; set; }
    public string Password { get; set; }
    public string VirtualHost { get; set; }
    public int Port { get; set; }
}
