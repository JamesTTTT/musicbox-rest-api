using Microsoft.AspNetCore.Mvc;
using musicboxapi.Models.Auth;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly AuthService _authService;

    public AuthController(AuthService authService)
    {
        _authService = authService;
    }

    // Register a new user
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterModel model)
    {
        try
        {
            var token = await _authService.RegisterAsync(model);
            return Ok(new { Token = token });
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }

    // Login user
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        try
        {
            var token = await _authService.LoginAsync(model);
            return Ok(new { Token = token });
        }
        catch (Exception ex)
        {
            return Unauthorized(ex.Message);
        }
    }

    // Confirm email
    [HttpPost("confirm-email")]
    public async Task<IActionResult> ConfirmEmail([FromBody] ConfirmEmailModel model)
    {
        try
        {
            await _authService.ConfirmEmailAsync(model.Email, model.Token);
            return Ok(new { Message = "Email confirmed successfully." });
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }

    // Forgot password
    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordModel model)
    {
        try
        {
            await _authService.ForgotPasswordAsync(model.Email);
            return Ok(new { Message = "Password reset email sent." });
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }

    // Reset password
    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordModel model)
    {
        try
        {
            await _authService.ResetPasswordAsync(model);
            return Ok(new { Message = "Password reset successfully." });
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }
}