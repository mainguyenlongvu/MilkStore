using MilkStore.Core.Base;

namespace MilkStore.Contract.Repositories.Entity
{
    public class Voucher : BaseEntity
    {
        public string Description { get; set; }
        public int SalePrice { get; set; }
        public int SalePercent { get; set; }
        public int LimitSalePrice { get; set; }
        public DateTime ExpiryDate { get; set; }
        public int UsingLimit { get; set; }
        public int UsedCount { get; set; }
        public int Status { get; set; }
        public string Name { get; set; } = string.Empty;

        public virtual ICollection<Order> Orders { get; set; }
    }
}