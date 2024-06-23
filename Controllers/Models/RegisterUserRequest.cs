namespace AspNetCoreBasicAuth.Controllers.Models;

public record RegisterUserRequest(string Email, string Password, string FirstName, string LastName, Role Role);