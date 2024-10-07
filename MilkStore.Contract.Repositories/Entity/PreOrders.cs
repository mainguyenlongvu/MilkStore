using MilkStore.Core.Base;
using MilkStore.Repositories.Entity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace MilkStore.Contract.Repositories.Entity
{
    public enum PreOrderStatus
    {
        Pending,
        Available,
        Confirmed
    }
    public class PreOrders : BaseEntity
    {
        public required Guid UserID { get; set; }
        public string ProductID { get; set; }        
        public PreOrderStatus Status { get; set; }
        public int Quantity { get; set; }
        [ForeignKey("ProductID")]
        public virtual Products Products { get; set; }
        public virtual ApplicationUser User { get; set; } // Một đơn hàng thuộc về một người dùng
    }
}
