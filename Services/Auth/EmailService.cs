namespace musicboxapi.Services.Auth;

public class EmailService
{
    public async Task SendConfirmationEmailAsync(string email, string token)
    {
        var confirmationLink = $"https://yourapi.com/confirm-email?email={email}&token={token}";
    }

    public async Task SendPasswordResetEmailAsync(string email, string token)
    {
        var resetLink = $"https://yourapi.com/reset-password?email={email}&token={token}";
    }
}