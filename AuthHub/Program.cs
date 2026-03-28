using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// So we get raw claim names (email, preferred_username, etc.)
JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

// Bind JWT bearer auth to Azure AD config.
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = "https://login.microsoftonline.com/common/v2.0";
        options.Audience = builder.Configuration["AzureAd:ClientId"]; // this is important for multi-tenant apps

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            RoleClaimType = ClaimTypes.Role,
            IssuerValidator = (issuer, token, parameters) =>
            {
                var validAuthority = "https://login.microsoftonline.com";
                if (!issuer.StartsWith(validAuthority))
                    throw new SecurityTokenInvalidIssuerException($"Invalid issuer {issuer}");
                return issuer;
            }
        };

        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = context =>
            {
                var identity = context.Principal.Identity as ClaimsIdentity;

                var email =
                    context.Principal.FindFirst("preferred_username")?.Value ??
                    context.Principal.FindFirst("email")?.Value ??
                    context.Principal.FindFirst("upn")?.Value;

                var domain = email?.Split("@").Last()?.ToLower();

                if (domain == "gmail.com")
                {
                    identity?.AddClaim(new Claim(ClaimTypes.Role, "GmailUser"));
                }

                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// app.UseHttpsRedirection();

// Enable authentication & authorization
app.UseAuthentication();
app.UseAuthorization();

// Simple test endpoint
app.MapGet("/", () => "Multi-tenant auth API is running.");

// /whoami endpoint that returns email from token
app.MapGet("/whoami", (HttpContext ctx) =>
{
    if (!ctx.User.Identity?.IsAuthenticated ?? true)
    {
        return Results.Unauthorized();
    }

    var email =
        ctx.User.FindFirst("preferred_username")?.Value ??
        ctx.User.FindFirst("email")?.Value ??
        ctx.User.FindFirst("upn")?.Value ??
        "unknown";

    var name =
        ctx.User.FindFirst("name")?.Value ??
        ctx.User.Identity?.Name ??
        email;

    var role = ctx.User.FindFirst(ClaimTypes.Role)?.Value ?? "none";

    return Results.Ok(new
    {
        email,
        name,
        role
    });
}).RequireAuthorization();

// Force bind to HTTP for LAN/WAN access
app.Urls.Clear();
app.Urls.Add("http://0.0.0.0:5058");

app.Run();