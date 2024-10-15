using MilkStore.Core.Base;
using System.ComponentModel.DataAnnotations;

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


        [StringLength(6, ErrorMessage = "Mã voucher phải có đúng 6 ký tự.")]
        public string VoucherCode { get; set; }
        

    }
}