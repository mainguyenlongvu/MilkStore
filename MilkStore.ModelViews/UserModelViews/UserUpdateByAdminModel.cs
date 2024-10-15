using System.ComponentModel.DataAnnotations;

namespace MilkStore.ModelViews.UserModelViews
{
    public class UserUpdateByAdminModel : UserUpdateModelView
    {
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&.])[A-Za-z\d@$!%*?&.]{8,16}$", ErrorMessage = "Mật khẩu phải có ít nhất 8 ký tự, 1 chữ hoa, 1 chữ thường, 1 số và 1 ký tự đặc biệt")]
        public string? Password { get; set; }
    }
}