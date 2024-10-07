using System.ComponentModel.DataAnnotations;
namespace MilkStore.ModelViews.AuthModelViews;
public class ResetPasswordModel
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Email is invalid")]
    public string Email { get; set; }
    [Required(ErrorMessage = "Password is required")]
    [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&.])[A-Za-z\d@$!%*?&.]{8,16}$", ErrorMessage = "Password must be at least 8 characters, 1 uppercase, 1 lowercase, 1 number and 1 special character")]
    public string Password { get; set; }
}