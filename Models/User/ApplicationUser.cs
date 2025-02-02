using Microsoft.AspNetCore.Identity;

namespace musicboxapi.Models.User;

public class ApplicationUser : IdentityUser
{
    public string? DisplayName { get; set; }
    public string? ProfilePictureUrl { get; set; }
    public bool IsEmailConfirmed { get; set; } // For email confirmation
    public string? ResetPasswordToken { get; set; } // For password reset
    public DateTime? ResetPasswordTokenExpiry { get; set; } // For password reset
}