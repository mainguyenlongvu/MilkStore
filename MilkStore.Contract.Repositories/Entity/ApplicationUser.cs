using Microsoft.AspNetCore.Identity;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Core.Utils;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace MilkStore.Repositories.Entity
{
    public class ApplicationUser : IdentityUser<Guid>
    {
        public int Points { get; set; } = 0;
        public string Name { get; set; }

        public string? ShippingAddress { get; set; }
        public string? CreatedBy { get; set; }
        public string? LastUpdatedBy { get; set; }
        public string? DeletedBy { get; set; }
        public DateTimeOffset CreatedTime { get; set; }
        public DateTimeOffset LastUpdatedTime { get; set; }
        public DateTimeOffset? DeletedTime { get; set; }
        public virtual ICollection<ApplicationUserLogins> Logins { get; set; } = new List<ApplicationUserLogins>();
        public virtual ICollection<ApplicationUserRoles> UserRoles { get; set; } = new List<ApplicationUserRoles>();

        // Thuộc tính số dư mới
        public double Balance { get; set; } = 0.0;  // Số dư tài khoản của người dùng

        public ApplicationUser()
        {
            CreatedTime = CoreHelper.SystemTimeNow;
            LastUpdatedTime = CreatedTime;
        }
        public virtual ICollection<TransactionHistory> TransactionHistories { get; set; } = new List<TransactionHistory>();


        [ForeignKey("Manager")]
        public Guid? ManagerId { get; set; }

        [InverseProperty("Members")]
        public virtual ApplicationUser? Manager { get; set; }

        [InverseProperty("Manager")]
        public virtual ICollection<ApplicationUser> Members { get; set; } = new List<ApplicationUser>();

        public virtual ICollection<Order> Orders { get; set; } // Một người dùng có nhiều đơn hàng
        public virtual ICollection<OrderGift> orderGift { get; set; }
    }
}