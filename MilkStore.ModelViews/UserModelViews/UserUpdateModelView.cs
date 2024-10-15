using System.ComponentModel.DataAnnotations;

namespace MilkStore.ModelViews.UserModelViews;
public class UserUpdateModelView
{
    [Required(ErrorMessage = "Số điện thoại không được để trống")]
    [Phone(ErrorMessage = "Số điện thoại không hợp lệ")]
    public string? PhoneNumber { get; set; }
    [Required(ErrorMessage = "Tên không được để trống")]
    [StringLength(100, ErrorMessage = "Tên không được quá dài")]
    public string Name { get; set; }

    [EmailAddress(ErrorMessage = "Email không hợp lệ")]
    public string Email { get; set; }

    [Required(ErrorMessage = "Địa chỉ không được để trống")]
    public string ShippingAddress { get; set; }
}