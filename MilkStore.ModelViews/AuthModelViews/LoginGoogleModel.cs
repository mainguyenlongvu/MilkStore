
using System.ComponentModel.DataAnnotations;

namespace MilkStore.ModelViews.AuthModelViews;
public class LoginGoogleModel
{
    [Required(ErrorMessage = "Email bắt buộc")]
    [EmailAddress(ErrorMessage = "Email không hợp lệ")]
    public string Email { get; set; }
    public string ProviderKey { get; set; }
}