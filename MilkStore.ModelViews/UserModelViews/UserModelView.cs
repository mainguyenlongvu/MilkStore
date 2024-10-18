
using System.ComponentModel.DataAnnotations;


namespace MilkStore.ModelViews.UserModelViews
{
    public class UserModelView
    {
        [Required(ErrorMessage = "Tên không được để trống")]
        public string Name { get; set; }
        [Required(ErrorMessage = "Email không được để trống")]
        [EmailAddress(ErrorMessage = "Email không hợp lệ")]
        public string Email { get; set; }
        [Required(ErrorMessage = "Số điện thoại không được để trống")]
        [Phone(ErrorMessage = "Số điện thoại không hợp lệ")]
        public string? PhoneNumber { get; set; }
        [Required(ErrorMessage = "Quyền truy cập không được để trống")]

        public string RoleID { get; set; }

        [Range(0, double.MaxValue, ErrorMessage = "Số tiền phải lớn hơn hoặc bằng 0")]
        public double Balance { get; set; } = 0;
    }
}
