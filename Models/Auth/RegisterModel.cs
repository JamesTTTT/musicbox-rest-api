namespace musicboxapi.Models.Auth;

public class RegisterModel
{
    public string Email { get; set; }
    public string Password { get; set; }
    public string DisplayName { get; set; }
    public string? ProfilePictureUrl { get; set; }
}