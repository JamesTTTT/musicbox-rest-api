using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using musicboxapi.Models.Auth;
using musicboxapi.Models.User;
using musicboxapi.Services.Auth;

public class AuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IConfiguration _configuration;
    private readonly EmailService _emailService;

    public AuthService(UserManager<ApplicationUser> userManager, IConfiguration configuration, EmailService emailService)
    {
        _userManager = userManager;
        _configuration = configuration;
        _emailService = emailService;
    }

    // Register a new user
    public async Task<string> RegisterAsync(RegisterModel model)
    {
        var user = new ApplicationUser
        {
            UserName = model.Email,
            Email = model.Email,
            DisplayName = model.DisplayName,
            ProfilePictureUrl = model.ProfilePictureUrl,
            IsEmailConfirmed = false // Email is not confirmed initially
        };

        var result = await _userManager.CreateAsync(user, model.Password);

        if (!result.Succeeded)
        {
            throw new Exception(string.Join(", ", result.Errors.Select(e => e.Description)));
        }

        // Send email confirmation
        var emailConfirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        await _emailService.SendConfirmationEmailAsync(user.Email, emailConfirmationToken);

        return GenerateJwtToken(user);
    }

    // Login user
    public async Task<string> LoginAsync(LoginModel model)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);

        if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
        {
            throw new Exception("Invalid login attempt.");
        }

        if (!user.IsEmailConfirmed)
        {
            throw new Exception("Email not confirmed.");
        }

        return GenerateJwtToken(user);
    }

    // Confirm email
    public async Task ConfirmEmailAsync(string email, string token)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            throw new Exception("User not found.");
        }

        var result = await _userManager.ConfirmEmailAsync(user, token);
        if (!result.Succeeded)
        {
            throw new Exception(string.Join(", ", result.Errors.Select(e => e.Description)));
        }
    }

    // Forgot password
    public async Task ForgotPasswordAsync(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            throw new Exception("User not found.");
        }

        var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
        user.ResetPasswordToken = resetToken;
        user.ResetPasswordTokenExpiry = DateTime.UtcNow.AddHours(1); // Token expires in 1 hour

        await _userManager.UpdateAsync(user);

        await _emailService.SendPasswordResetEmailAsync(email, resetToken);
    }

    // Reset password
    public async Task ResetPasswordAsync(ResetPasswordModel model)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null || user.ResetPasswordToken != model.Token || user.ResetPasswordTokenExpiry < DateTime.UtcNow)
        {
            throw new Exception("Invalid token or user.");
        }

        var result = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);
        if (!result.Succeeded)
        {
            throw new Exception(string.Join(", ", result.Errors.Select(e => e.Description)));
        }
        
        user.ResetPasswordToken = null;
        user.ResetPasswordTokenExpiry = null;
        await _userManager.UpdateAsync(user);
    }

    // Generate JWT token
    private string GenerateJwtToken(ApplicationUser user)
    {
        var jwtSettings = _configuration.GetSection("Jwt");
        var key = Encoding.ASCII.GetBytes(jwtSettings["Key"]);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Email, user.Email)
            }),
            Expires = DateTime.UtcNow.AddMinutes(Convert.ToDouble(jwtSettings["ExpiryInMinutes"])),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
            Issuer = jwtSettings["Issuer"],
            Audience = jwtSettings["Audience"]
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}
