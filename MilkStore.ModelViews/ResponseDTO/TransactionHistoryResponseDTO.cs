using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.ModelViews.ResponseDTO
{
    public class TransactionHistoryResponseDTO
    {
        public Guid Id { get; set; }
        public Guid UserId { get; set; }
        public DateTimeOffset TransactionDate { get; set; }
        public string Type { get; set; }
        public double Amount { get; set; }
        public double BalanceAfterTransaction { get; set; }
        public string? Content { get; set; }
    }
}
