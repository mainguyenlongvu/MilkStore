using MilkStore.Core.Base;
using MilkStore.Repositories.Entity;
using System.ComponentModel.DataAnnotations.Schema;

namespace MilkStore.Contract.Repositories.Entity
{
    public enum OrderGiftStatus
    {
        Isnull,
        Pending,
        Confirmed,
        Cancelled,
        Delivering,
        Delivered,
        Refunded
    }
    public class OrderGift : BaseEntity
    {
        public string Address { get; set; }
        public required Guid UserID { get; set; }
        public OrderGiftStatus Status { get; set; }
        public virtual ApplicationUser User { get; set; }
        public virtual ICollection<OrderDetailGift> OGifts { get; set; }
    }
}