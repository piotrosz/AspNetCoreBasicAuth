using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AspNetCoreBasicAuth.Options;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AspNetCoreBasicAuth.Services;

public sealed class IdentityTokenCreator
{
    private readonly JwtSettings? _settings;
    private readonly byte[] _key;

    public IdentityTokenCreator(IOptions<JwtSettings> jwtOptions)
    {
        _settings = jwtOptions.Value;
        ArgumentNullException.ThrowIfNull(_settings);
        ArgumentNullException.ThrowIfNull(_settings.SigningKey);
        ArgumentNullException.ThrowIfNull(_settings.Audiences);
        ArgumentNullException.ThrowIfNull(_settings.Issuer);
        _key = Encoding.ASCII.GetBytes(_settings?.SigningKey!);
    }

    private static JwtSecurityTokenHandler TokenHandler => new();

    public string CreateToken(ClaimsIdentity identity)
    {
        var tokenDescriptor = GetTokenDescriptor(identity);
        var token = TokenHandler.CreateToken(tokenDescriptor);
        return TokenHandler.WriteToken(token);
    }

    private SecurityToken CreateSecurityToken(ClaimsIdentity identity)
    {
        var tokenDescriptor = GetTokenDescriptor(identity);
        return TokenHandler.CreateToken(tokenDescriptor);
    }

    private SecurityTokenDescriptor GetTokenDescriptor(ClaimsIdentity identity)
    {
        return new SecurityTokenDescriptor
        {
            Subject = identity,
            Expires = DateTime.Now.AddHours(2),
            Audience = _settings.Audiences[0],
            Issuer = _settings.Issuer,
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(_key),
                SecurityAlgorithms.HmacSha256Signature)
        };
    }
}