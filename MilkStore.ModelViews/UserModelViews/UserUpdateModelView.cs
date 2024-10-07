using System.ComponentModel.DataAnnotations;

namespace MilkStore.ModelViews.UserModelViews;
public class UserUpdateModelView
{
    [Required(ErrorMessage = "PhoneNumber is required")]
    [Phone(ErrorMessage = "Phone number is invalid")]
    public string? PhoneNumber { get; set; }
    [Required(ErrorMessage = "Name is required")]
    public string Name { get; set; }
}