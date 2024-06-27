using System.Security.Claims;
using AspNetCoreBasicAuth.Controllers.Models;
using AspNetCoreBasicAuth.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;

namespace AspNetCoreBasicAuth.Controllers;

[Route("[controller]")]
[ApiController]
public class AccountsController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IdentityTokenCreator _identityTokenCreator;

    public AccountsController(
        UserManager<IdentityUser> userManager, 
        SignInManager<IdentityUser> signInManager, 
        RoleManager<IdentityRole> roleManager, 
        IdentityTokenCreator identityTokenCreator)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _roleManager = roleManager;
        _identityTokenCreator = identityTokenCreator;
    }

    [HttpPost]
    [Route("register")]
    public async Task<IActionResult> Register(RegisterUserRequest registerUserRequest)
    {
        var identity = new IdentityUser { Email = registerUserRequest.Email, UserName = registerUserRequest.Email };
        var createdIdentity = await _userManager.CreateAsync(identity, registerUserRequest.Password);

        var newClaims = new List<Claim>
        {
            new("FirstName", registerUserRequest.FirstName),
            new("LastName", registerUserRequest.LastName)
        };

        await _userManager.AddClaimsAsync(identity, newClaims);

        const string administratorRoleName = "Administrator";
        if (registerUserRequest.Role == Role.Administrator)
        {
            var role = await _roleManager.FindByNameAsync(administratorRoleName);
            if (role == null)
            {
                role = new IdentityRole(administratorRoleName);
                await _roleManager.CreateAsync(role);
            }

            await _userManager.AddToRoleAsync(identity, administratorRoleName);
            newClaims.Add(new Claim(ClaimTypes.Role, administratorRoleName));
        }
        
        const string userRoleName = "User";
        if(registerUserRequest.Role == Role.User)
        {
            var role = await _roleManager.FindByNameAsync(userRoleName);
            if (role == null)
            {
                role = new IdentityRole(userRoleName);
                await _roleManager.CreateAsync(role);
            }

            await _userManager.AddToRoleAsync(identity, userRoleName);
            newClaims.Add(new Claim(ClaimTypes.Role, userRoleName));
        }

        var claimsIdentity = new ClaimsIdentity(new Claim[]
        {
            new(JwtRegisteredClaimNames.Sub, identity.Email ?? throw new InvalidOperationException()),
            new(JwtRegisteredClaimNames.Email, identity.Email ?? throw new InvalidOperationException()),
        });

        claimsIdentity.AddClaims(newClaims);

        var token = _identityTokenCreator.CreateToken(claimsIdentity);
        return Ok(new AuthenticationResult(token));
    }

    [HttpPost]
    [Route("login")]
    public async Task<IActionResult> Login(LoginUserRequest loginUserRequest)
    {
        var user = await _userManager.FindByEmailAsync(loginUserRequest.Email);
        if (user is null) return BadRequest();

        var result = await _signInManager.CheckPasswordSignInAsync(user, loginUserRequest.Password, lockoutOnFailure: false);
        if (!result.Succeeded) return BadRequest("Could not sign in");

        var claims = await _userManager.GetClaimsAsync(user);
        var roles = await _userManager.GetRolesAsync(user);

        var claimsIdentity = new ClaimsIdentity(new Claim[]
        {
            new(JwtRegisteredClaimNames.Sub, user.Email ?? throw new InvalidOperationException()),
            new(JwtRegisteredClaimNames.Email, user.Email ?? throw new InvalidOperationException()),
        });

        claimsIdentity.AddClaims(claims);

        foreach (var role in roles)
        {
            claimsIdentity.AddClaim(new Claim(ClaimTypes.Role, role));
        }

        var token = _identityTokenCreator.CreateToken(claimsIdentity);
        return Ok( new AuthenticationResult(token));
    }
}