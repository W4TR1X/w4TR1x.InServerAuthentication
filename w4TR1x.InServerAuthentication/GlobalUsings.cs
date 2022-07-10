﻿global using Microsoft.AspNetCore.Authentication;
global using Microsoft.AspNetCore.Authentication.Cookies;
global using Microsoft.AspNetCore.Authentication.JwtBearer;
global using Microsoft.AspNetCore.DataProtection;
global using Microsoft.AspNetCore.Http;
global using Microsoft.Extensions.DependencyInjection;
global using Microsoft.Extensions.Logging;
global using Microsoft.Extensions.Options;
global using Microsoft.IdentityModel.Tokens;
global using System.Collections.Concurrent;
global using System.Security.Claims;
global using System.Security.Principal;
global using System.Text;
global using System.Text.Encodings.Web;
global using w4TR1x.InServerAuthentication.Interfaces;
global using w4TR1x.InServerAuthentication.Models;
global using w4TR1x.InServerAuthentication.Models.AuthenticationSystems;