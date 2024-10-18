using MilkStore.Core.Base;
using MilkStore.Repositories.Entity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.Contract.Repositories.Entity
{
    public enum TransactionType
    {
        Vnpay,
        UserWallet,
    }

    public class TransactionHistory : BaseEntity
    {
        public Guid UserId { get; set; }

        [ForeignKey("UserId")]
        public virtual ApplicationUser User { get; set; } // Gắn với người dùng

        public DateTimeOffset TransactionDate { get; set; } // Ngày thực hiện giao dịch

        public TransactionType Type { get; set; } // Loại giao dịch (Nạp tiền hoặc rút tiền)

        public double Amount { get; set; } // Số tiền của giao dịch

        public double BalanceAfterTransaction { get; set; } // Số dư sau giao dịch
        public string? Content { get; set; } // Nội dung giao dịch
    }

}
