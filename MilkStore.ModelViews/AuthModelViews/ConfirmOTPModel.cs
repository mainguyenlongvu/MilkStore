using System.ComponentModel.DataAnnotations;
namespace MilkStore.ModelViews.AuthModelViews;
public class ConfirmOTPModel
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Email is invalid")]
    public string Email { get; set; }
    [Required(ErrorMessage = "OTP is required")]
    [MaxLength(6, ErrorMessage = "OTP is invalid")]
    [MinLength(0, ErrorMessage = "OTP is invalid")]
    [StringLength(6, ErrorMessage = "OTP is invalid")]
    [RegularExpression(@"^\d{6}$", ErrorMessage = "OTP is invalid")]
    public string OTP { get; set; }
}