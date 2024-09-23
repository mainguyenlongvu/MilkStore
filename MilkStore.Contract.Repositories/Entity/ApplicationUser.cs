using Microsoft.AspNetCore.Identity;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Core.Utils;
using System.ComponentModel.DataAnnotations;

namespace MilkStore.Repositories.Entity
{
    public class ApplicationUser : IdentityUser<Guid>
    {
        public int Points { get; set; } = 0;
        public string Password { get; set; } =string.Empty;
        public string? CreatedBy { get; set; }
        public string? LastUpdatedBy { get; set; }
        public string? DeletedBy { get; set; }
        public DateTimeOffset CreatedTime { get; set; }
        public DateTimeOffset LastUpdatedTime { get; set; }
        public DateTimeOffset? DeletedTime { get; set; }
        public ApplicationUser()
        {
            CreatedTime = CoreHelper.SystemTimeNow;
            LastUpdatedTime = CreatedTime;
        }

        public virtual ICollection<Order> Orders { get; set; } // Một người dùng có nhiều đơn hàng
    }
}
